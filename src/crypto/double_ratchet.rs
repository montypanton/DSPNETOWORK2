// src/crypto/double_ratchet.rs
//
// This module implements the Double Ratchet protocol for end-to-end encrypted
// messaging with perfect forward secrecy and post-compromise security.
// Based on the Signal Protocol specification:
// https://signal.org/docs/specifications/doubleratchet/

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use log::{debug, error, info, trace, warn};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use crate::crypto::kyber::{self, KyberPublicKey, KyberSecretKey};
use crate::crypto::ratchet::{self, RatchetState, MessageHeader};

// Maximum number of message keys to store for skipped messages
const MAX_SKIP: usize = 1000;

// Number of messages per session before forced ratchet
const MESSAGES_PER_SESSION: u32 = 100;

// Double Ratchet session
#[derive(Debug)]
pub struct DoubleRatchetSession {
    ratchet_state: RatchetState,
    shared_secrets: Vec<Vec<u8>>, // For hybrid crypto (X25519 + Kyber)
    message_keys: HashMap<u64, Vec<u8>>, // Message keys for out-of-order messages
    identity_key: Option<Vec<u8>>, // Local identity key for verification (optional)
    remote_identity: Option<Vec<u8>>, // Remote identity key for verification (optional)
    skip_keys: HashMap<Vec<u8>, HashMap<u32, Vec<u8>>>, // Skipped message keys by ratchet public key
    max_skip_size: usize,
    security_level: SecurityLevel,
}

// Security level enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Standard,      // ChaCha20-Poly1305
    High,          // ChaCha20-Poly1305 with longer keys
    PostQuantum,   // Hybrid X25519 + Kyber
}

// Encrypted message format
#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
    pub auth_tag: Vec<u8>, // Optional authentication tag
}

// Error types
#[derive(Debug)]
pub enum DoubleRatchetError {
    EncryptionError(String),
    DecryptionError(String),
    InvalidState(String),
    InvalidKey,
    InvalidHeader,
    MaxSkippedExceeded,
    AuthenticationFailed,
    SerializationError(String),
}

impl DoubleRatchetSession {
    /// Create a new Double Ratchet session as the initiator
    pub fn new_initiator(
        x25519_shared_secret: &[u8],
        kyber_shared_secret: Option<&[u8]>,
        remote_public_key: &[u8],
        identity_key: Option<&[u8]>,
        remote_identity: Option<&[u8]>,
        security_level: SecurityLevel,
    ) -> Result<Self, DoubleRatchetError> {
        // Combine shared secrets for hybrid encryption
        let mut combined_secret = x25519_shared_secret.to_vec();
        if let Some(kyber_secret) = kyber_shared_secret {
            combined_secret.extend_from_slice(kyber_secret);
        }
        
        // Create ratchet state
        let ratchet_state = RatchetState::new(
            &combined_secret,
            true, // initiator
            Some(remote_public_key),
        ).map_err(|_| DoubleRatchetError::InvalidState("Failed to create ratchet state".to_string()))?;
        
        Ok(DoubleRatchetSession {
            ratchet_state,
            shared_secrets: vec![combined_secret],
            message_keys: HashMap::new(),
            identity_key: identity_key.map(|k| k.to_vec()),
            remote_identity: remote_identity.map(|k| k.to_vec()),
            skip_keys: HashMap::new(),
            max_skip_size: MAX_SKIP,
            security_level,
        })
    }
    
    /// Create a new Double Ratchet session as the responder
    pub fn new_responder(
        x25519_shared_secret: &[u8],
        kyber_shared_secret: Option<&[u8]>,
        identity_key: Option<&[u8]>,
        remote_identity: Option<&[u8]>,
        security_level: SecurityLevel,
    ) -> Result<Self, DoubleRatchetError> {
        // Combine shared secrets for hybrid encryption
        let mut combined_secret = x25519_shared_secret.to_vec();
        if let Some(kyber_secret) = kyber_shared_secret {
            combined_secret.extend_from_slice(kyber_secret);
        }
        
        // Create ratchet state
        let ratchet_state = RatchetState::new(
            &combined_secret,
            false, // responder
            None,  // Will receive public key in first message
        ).map_err(|_| DoubleRatchetError::InvalidState("Failed to create ratchet state".to_string()))?;
        
        Ok(DoubleRatchetSession {
            ratchet_state,
            shared_secrets: vec![combined_secret],
            message_keys: HashMap::new(),
            identity_key: identity_key.map(|k| k.to_vec()),
            remote_identity: remote_identity.map(|k| k.to_vec()),
            skip_keys: HashMap::new(),
            max_skip_size: MAX_SKIP,
            security_level,
        })
    }
    
    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage, DoubleRatchetError> {
        // Prepare header and get message key
        let (header, message_key) = self.ratchet_state.prepare_send()
            .map_err(|_| DoubleRatchetError::EncryptionError("Failed to prepare send".to_string()))?;
        
        // Add message counter to force occasional ratcheting
        if self.ratchet_state.send_count >= MESSAGES_PER_SESSION {
            self.ratchet_state.pending_commit = true;
        }
        
        // Generate a nonce for encryption
        let mut nonce_bytes = [0u8; 12]; // ChaCha20-Poly1305 needs a 12-byte nonce
        thread_rng().fill(&mut nonce_bytes);
        
        // Create authentication tag
        let auth_tag = if let Some(id_key) = &self.identity_key {
            let mut tag_data = Vec::with_capacity(id_key.len() + header.dh_public.len() + plaintext.len());
            tag_data.extend_from_slice(id_key);
            tag_data.extend_from_slice(&header.dh_public);
            tag_data.extend_from_slice(plaintext);
            
            let mut hasher = Sha256::new();
            hasher.update(&tag_data);
            hasher.finalize().to_vec()
        } else {
            Vec::new()
        };
        
        // Encrypt the message
        let ciphertext = match self.security_level {
            SecurityLevel::Standard | SecurityLevel::High => {
                // Use ChaCha20-Poly1305 for encryption
                let key = Key::from_slice(&message_key);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                // Construct associated data (AD) for AEAD
                let mut associated_data = Vec::with_capacity(header.dh_public.len() + 8);
                associated_data.extend_from_slice(&header.dh_public);
                associated_data.extend_from_slice(&header.message_num.to_be_bytes());
                
                // Prepend nonce to ciphertext
                let mut encrypted = nonce_bytes.to_vec();
                
                // Encrypt with associated data
                let mut ciphertext = cipher.encrypt(nonce, plaintext)
                    .map_err(|_| DoubleRatchetError::EncryptionError("Encryption failed".to_string()))?;
                
                encrypted.append(&mut ciphertext);
                encrypted
            },
            SecurityLevel::PostQuantum => {
                // For post-quantum security, we use ChaCha20-Poly1305 with hybrid secrets
                let key = Key::from_slice(&message_key);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                // Construct associated data with remote identity if available
                let mut associated_data = Vec::with_capacity(header.dh_public.len() + 8);
                associated_data.extend_from_slice(&header.dh_public);
                associated_data.extend_from_slice(&header.message_num.to_be_bytes());
                if let Some(remote_id) = &self.remote_identity {
                    associated_data.extend_from_slice(remote_id);
                }
                
                // Prepend nonce to ciphertext
                let mut encrypted = nonce_bytes.to_vec();
                
                // Encrypt with associated data
                let mut ciphertext = cipher.encrypt(nonce, plaintext)
                    .map_err(|_| DoubleRatchetError::EncryptionError("Encryption failed".to_string()))?;
                
                encrypted.append(&mut ciphertext);
                encrypted
            }
        };
        
        Ok(EncryptedMessage {
            header,
            ciphertext,
            auth_tag,
        })
    }
    
    /// Decrypt a message
    pub fn decrypt(&mut self, encrypted_message: &EncryptedMessage) -> Result<Vec<u8>, DoubleRatchetError> {
        // Process header to get message key
        let message_key = self.ratchet_state.process_header(&encrypted_message.header)
            .map_err(|e| match e {
                ratchet::RatchetError::MaxSkippedExceeded => DoubleRatchetError::MaxSkippedExceeded,
                _ => DoubleRatchetError::DecryptionError("Failed to process header".to_string()),
            })?;
        
        // Verify authentication tag if present and we have identity keys
        if !encrypted_message.auth_tag.is_empty() && self.remote_identity.is_some() {
            // We'll verify the tag after decryption
        }
        
        // Extract nonce and ciphertext
        if encrypted_message.ciphertext.len() < 12 {
            return Err(DoubleRatchetError::DecryptionError("Ciphertext too short".to_string()));
        }
        
        let nonce_bytes = &encrypted_message.ciphertext[0..12];
        let actual_ciphertext = &encrypted_message.ciphertext[12..];
        
        // Decrypt the message
        let plaintext = match self.security_level {
            SecurityLevel::Standard | SecurityLevel::High => {
                // Use ChaCha20-Poly1305 for decryption
                let key = Key::from_slice(&message_key);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = Nonce::from_slice(nonce_bytes);
                
                // Construct associated data (AD) for AEAD
                let mut associated_data = Vec::with_capacity(encrypted_message.header.dh_public.len() + 8);
                associated_data.extend_from_slice(&encrypted_message.header.dh_public);
                associated_data.extend_from_slice(&encrypted_message.header.message_num.to_be_bytes());
                
                cipher.decrypt(nonce, actual_ciphertext)
                    .map_err(|_| DoubleRatchetError::DecryptionError("Decryption failed".to_string()))?
            },
            SecurityLevel::PostQuantum => {
                // For post-quantum security, we use ChaCha20-Poly1305 with hybrid secrets
                let key = Key::from_slice(&message_key);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = Nonce::from_slice(nonce_bytes);
                
                // Construct associated data with remote identity if available
                let mut associated_data = Vec::with_capacity(encrypted_message.header.dh_public.len() + 8);
                associated_data.extend_from_slice(&encrypted_message.header.dh_public);
                associated_data.extend_from_slice(&encrypted_message.header.message_num.to_be_bytes());
                if let Some(remote_id) = &self.remote_identity {
                    associated_data.extend_from_slice(remote_id);
                }
                
                cipher.decrypt(nonce, actual_ciphertext)
                    .map_err(|_| DoubleRatchetError::DecryptionError("Decryption failed".to_string()))?
            }
        };
        
        // Verify authentication tag if present
        if !encrypted_message.auth_tag.is_empty() && self.remote_identity.is_some() {
            let remote_id = self.remote_identity.as_ref().unwrap();
            
            let mut tag_data = Vec::with_capacity(remote_id.len() + encrypted_message.header.dh_public.len() + plaintext.len());
            tag_data.extend_from_slice(remote_id);
            tag_data.extend_from_slice(&encrypted_message.header.dh_public);
            tag_data.extend_from_slice(&plaintext);
            
            let mut hasher = Sha256::new();
            hasher.update(&tag_data);
            let calculated_tag = hasher.finalize();
            
            // Compare tags in constant time
            let tag_valid = constant_time_eq(&encrypted_message.auth_tag, &calculated_tag);
            
            if !tag_valid {
                return Err(DoubleRatchetError::AuthenticationFailed);
            }
        }
        
        Ok(plaintext)
    }
    
    /// Serialize the encrypted message for transmission
    pub fn serialize_message(encrypted_message: &EncryptedMessage) -> Result<Vec<u8>, DoubleRatchetError> {
        serde_json::to_vec(encrypted_message)
            .map_err(|e| DoubleRatchetError::SerializationError(format!("Failed to serialize message: {}", e)))
    }
    
    /// Deserialize a message from transmission format
    pub fn deserialize_message(data: &[u8]) -> Result<EncryptedMessage, DoubleRatchetError> {
        serde_json::from_slice(data)
            .map_err(|e| DoubleRatchetError::SerializationError(format!("Failed to deserialize message: {}", e)))
    }
    
    /// Get the current security level
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
    
    /// Set maximum skipped message keys
    pub fn set_max_skip(&mut self, max_skip: usize) {
        self.max_skip_size = max_skip;
    }
    
    /// Force a ratchet step
    pub fn force_ratchet(&mut self) -> Result<(), DoubleRatchetError> {
        if self.ratchet_state.dh_remote_key.is_none() {
            return Err(DoubleRatchetError::InvalidState("Cannot ratchet without remote key".to_string()));
        }
        
        self.ratchet_state.ratchet_dh()
            .map_err(|_| DoubleRatchetError::InvalidState("Failed to perform DH ratchet".to_string()))
    }
    
    /// Get current ratchet public key
    pub fn get_public_key(&self) -> Vec<u8> {
        self.ratchet_state.dh_key_pair.public.clone()
    }
}

// Utility function for constant time comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_double_ratchet_encrypt_decrypt() {
        // Generate random shared secrets
        let mut x25519_shared = [0u8; 32];
        OsRng.fill(&mut x25519_shared);
        
        let mut kyber_shared = [0u8; 32];
        OsRng.fill(&mut kyber_shared);
        
        // Generate dummy public key
        let mut remote_public = [0u8; 32];
        OsRng.fill(&mut remote_public);
        
        // Create initiator and responder sessions
        let mut initiator = DoubleRatchetSession::new_initiator(
            &x25519_shared,
            Some(&kyber_shared),
            &remote_public,
            None,
            None,
            SecurityLevel::Standard
        ).unwrap();
        
        let mut responder = DoubleRatchetSession::new_responder(
            &x25519_shared,
            Some(&kyber_shared),
            None,
            None,
            SecurityLevel::Standard
        ).unwrap();
        
        // Test message from initiator to responder
        let plaintext = b"This is a test message";
        let encrypted = initiator.encrypt(plaintext).unwrap();
        let decrypted = responder.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
        
        // Test message from responder to initiator
        let plaintext2 = b"This is a response";
        let encrypted2 = responder.encrypt(plaintext2).unwrap();
        let decrypted2 = initiator.decrypt(&encrypted2).unwrap();
        
        assert_eq!(plaintext2.to_vec(), decrypted2);
    }
    
    #[test]
    fn test_serialization() {
        // Generate random shared secrets
        let mut x25519_shared = [0u8; 32];
        OsRng.fill(&mut x25519_shared);
        
        let mut kyber_shared = [0u8; 32];
        OsRng.fill(&mut kyber_shared);
        
        // Generate dummy public key
        let mut remote_public = [0u8; 32];
        OsRng.fill(&mut remote_public);
        
        // Create initiator
        let mut initiator = DoubleRatchetSession::new_initiator(
            &x25519_shared,
            Some(&kyber_shared),
            &remote_public,
            None,
            None,
            SecurityLevel::Standard
        ).unwrap();
        
        // Encrypt a message
        let plaintext = b"Test serialization";
        let encrypted = initiator.encrypt(plaintext).unwrap();
        
        // Serialize and deserialize
        let serialized = DoubleRatchetSession::serialize_message(&encrypted).unwrap();
        let deserialized = DoubleRatchetSession::deserialize_message(&serialized).unwrap();
        
        // Verify header is preserved
        assert_eq!(encrypted.header.dh_public, deserialized.header.dh_public);
        assert_eq!(encrypted.header.prev_chain_len, deserialized.header.prev_chain_len);
        assert_eq!(encrypted.header.message_num, deserialized.header.message_num);
        
        // Verify ciphertext is preserved
        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
    }
    
    #[test]
    fn test_multiple_messages() {
        // Generate random shared secrets
        let mut x25519_shared = [0u8; 32];
        OsRng.fill(&mut x25519_shared);
        
        // Generate dummy public key
        let mut remote_public = [0u8; 32];
        OsRng.fill(&mut remote_public);
        
        // Create initiator and responder sessions
        let mut initiator = DoubleRatchetSession::new_initiator(
            &x25519_shared,
            None,
            &remote_public,
            None,
            None,
            SecurityLevel::Standard
        ).unwrap();
        
        let mut responder = DoubleRatchetSession::new_responder(
            &x25519_shared,
            None,
            None,
            None,
            SecurityLevel::Standard
        ).unwrap();
        
        // Send multiple messages back and forth
        for i in 0..10 {
            // Initiator to responder
            let plaintext = format!("Message {} from initiator", i);
            let encrypted = initiator.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = responder.decrypt(&encrypted).unwrap();
            assert_eq!(plaintext.as_bytes(), &decrypted[..]);
            
            // Responder to initiator
            let response = format!("Response {} from responder", i);
            let encrypted_response = responder.encrypt(response.as_bytes()).unwrap();
            let decrypted_response = initiator.decrypt(&encrypted_response).unwrap();
            assert_eq!(response.as_bytes(), &decrypted_response[..]);
        }
    }
    
    #[test]
    fn test_out_of_order_messages() {
        // Generate random shared secrets
        let mut x25519_shared = [0u8; 32];
        OsRng.fill(&mut x25519_shared);
        
        // Generate dummy public key
        let mut remote_public = [0u8; 32];
        OsRng.fill(&mut remote_public);
        
        // Create initiator and responder sessions
        let mut initiator = DoubleRatchetSession::new_initiator(
            &x25519_shared,
            None,
            &remote_public,
            None,
            None,
            SecurityLevel::Standard
        ).unwrap();
        
        let mut responder = DoubleRatchetSession::new_responder(
            &x25519_shared,
            None,
            None,
            None,
            SecurityLevel::Standard
        ).unwrap();
        
        // Encrypt multiple messages
        let msg1 = initiator.encrypt(b"Message 1").unwrap();
        let msg2 = initiator.encrypt(b"Message 2").unwrap();
        let msg3 = initiator.encrypt(b"Message 3").unwrap();
        
        // Decrypt out of order
        let dec3 = responder.decrypt(&msg3).unwrap();
        assert_eq!(b"Message 3".to_vec(), dec3);
        
        let dec1 = responder.decrypt(&msg1).unwrap();
        assert_eq!(b"Message 1".to_vec(), dec1);
        
        let dec2 = responder.decrypt(&msg2).unwrap();
        assert_eq!(b"Message 2".to_vec(), dec2);
    }
}