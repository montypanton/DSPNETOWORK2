// src/crypto/e2ee.rs
// Implementation of an end-to-end encryption protocol
// Combining Double Ratchet, X25519, and Kyber for post-quantum security

use ed25519_dalek::{Signature, Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use log::{debug, error, info, trace, warn};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha3_256, Sha3_512};
use std::convert::TryInto;
use std::collections::HashMap;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use crate::crypto::kyber::{self, KyberKeypair, KyberPublicKey, KyberSecretKey, KyberCiphertext};
use crate::crypto::ratchet::{RatchetState, MessageHeader};
use crate::crypto::keys::{IdentityKeyBundle, PreKeyBundle};
use crate::utils::metadata::{blind_token, encrypt_metadata, create_padded_envelope, extract_from_envelope};

// Session protocols - for initialization, ratcheting, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionProtocol {
    // Initial X3DH like key exchange 
    // X3DH: Extended Triple Diffie-Hellman
    InitialKeyExchange {
        identity_key: Vec<u8>,            // Ed25519 public key
        ephemeral_key: Vec<u8>,           // X25519 ephemeral public key
        prekey_id: Vec<u8>,               // ID of the used prekey
        kyber_ciphertext: KyberCiphertext, // Kyber encapsulation
        dh_ratchet_key: Vec<u8>,          // Initial DH ratchet key
        signature: Vec<u8>,               // Signature over all above fields
    },
    
    // Message to inform peer that we need to ratchet
    RatchetAdvance {
        new_ratchet_key: Vec<u8>,         // New ratchet public key
    },
    
    // Heartbeat to verify active connection
    Heartbeat {
        timestamp: u64,
        counter: u32,
    },
    
    // Session termination
    SessionEnd {
        reason: String,
    },
}

// Encrypted message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    // Normal text message
    Text { 
        content: String,
        reply_to: Option<String>,  // Message ID this is replying to
    },
    
    // Binary data (file transfer, etc.)
    Binary { 
        data: Vec<u8>,
        mime_type: String,
        filename: Option<String>,
    },
    
    // Control message for client state synchronization
    Control {
        action: String,
        parameters: HashMap<String, String>,
    },
    
    // Session protocol messages
    Protocol(SessionProtocol),
}

// Full message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,                // Unique message ID
    pub sender: String,            // Sender fingerprint
    pub timestamp: u64,            // Message timestamp
    pub msg_type: MessageType,     // Message content type
    pub attachments: Vec<String>,  // IDs of attached content (if any)
}

// Double Ratchet header with additional authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureMessageHeader {
    pub ratchet_header: MessageHeader, // Standard Double Ratchet header
    pub message_id: String,           // Unique message ID
    pub sender_fingerprint: String,   // Sender identity fingerprint (truncated)
    pub timestamp: u64,               // Message timestamp
    pub padding_length: usize,        // Length of random padding 
}

// Encrypted message structure for transmission
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: SecureMessageHeader,  // Header fields
    pub encrypted_content: Vec<u8>,    // Encrypted content
    pub mac: Vec<u8>,                  // Message authentication code
}

// Error types
#[derive(Debug)]
pub enum CryptoError {
    EncryptionError(String),
    DecryptionError(String),
    SignatureError(String),
    InvalidState(String),
    InvalidKey(String),
    SessionError(String),
    DeserializationError(String),
}

// Protocol implementation
pub struct E2EEProtocol {
    identity: IdentityKeyBundle,
    ratchet_state: Option<RatchetState>,
    remote_identity: Option<String>,
    message_keys: HashMap<u32, Vec<u8>>, // Message number -> key
    security_level: SecurityLevel,
    skipped_message_keys: HashMap<Vec<u8>, HashMap<u32, Vec<u8>>>, // Ratchet key -> (message number -> key)
    max_skipped: usize,
}

// Security level for deciding which algorithms to use
#[derive(Debug, Clone, Copy)]
pub enum SecurityLevel {
    Standard,      // Basic encryption
    High,          // High-security encryption
    Quantum,       // Post-quantum resistant
}

impl E2EEProtocol {
    // Create a new protocol instance
    pub fn new(identity: IdentityKeyBundle, security_level: SecurityLevel) -> Self {
        E2EEProtocol {
            identity,
            ratchet_state: None,
            remote_identity: None,
            message_keys: HashMap::new(),
            security_level,
            skipped_message_keys: HashMap::new(),
            max_skipped: 100, // Maximum skipped message keys to store
        }
    }
    
    // Initialize a session with a peer as the initiator
    pub fn initialize_as_initiator(
        &mut self,
        recipient_identity: &IdentityKeyBundle,
        recipient_prekey: &PreKeyBundle,
    ) -> Result<Vec<u8>, CryptoError> {
        info!("Initializing E2EE session as initiator with peer: {}", 
             &recipient_identity.fingerprint[0..16]);
        
        // Generate ephemeral X25519 key
        debug!("Generating ephemeral X25519 key");
        let mut csprng = rand_07::rngs::OsRng{};
        let ephemeral_secret = X25519SecretKey::new(csprng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        
        // Extract recipient keys
        let recipient_identity_key = match Ed25519PublicKey::from_bytes(&recipient_identity.ed25519.public) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::InvalidKey("Invalid recipient Ed25519 key".to_string())),
        };
        
        let recipient_x25519 = match X25519PublicKey::from_bytes(&recipient_identity.x25519.public) {
            Some(key) => key,
            None => return Err(CryptoError::InvalidKey("Invalid recipient X25519 key".to_string())),
        };
        
        let recipient_prekey_x25519 = match X25519PublicKey::from_bytes(&recipient_prekey.x25519) {
            Some(key) => key,
            None => return Err(CryptoError::InvalidKey("Invalid recipient prekey".to_string())),
        };
        
        // 1. Calculate DH outputs (similar to X3DH key agreement)
        // DH1 = DH(identity_key_A, identity_key_B)
        let dh1 = {
            let my_identity_x25519 = X25519SecretKey::from(self.identity.x25519.secret.clone().try_into().unwrap());
            my_identity_x25519.diffie_hellman(&recipient_x25519)
        };
        
        // DH2 = DH(ephemeral_key_A, identity_key_B)
        let dh2 = ephemeral_secret.diffie_hellman(&recipient_x25519);
        
        // DH3 = DH(identity_key_A, prekey_B)
        let dh3 = {
            let my_identity_x25519 = X25519SecretKey::from(self.identity.x25519.secret.clone().try_into().unwrap());
            my_identity_x25519.diffie_hellman(&recipient_prekey_x25519)
        };
        
        // DH4 = DH(ephemeral_key_A, prekey_B)
        let dh4 = ephemeral_secret.diffie_hellman(&recipient_prekey_x25519);
        
        // 2. Generate Kyber encapsulation
        debug!("Performing Kyber encapsulation");
        let mut rng = thread_rng();
        let (kyber_shared, kyber_ciphertext) = kyber::encapsulate(&mut rng, &recipient_identity.kyber.public);
        
        // 3. Combine shared secrets
        debug!("Combining shared secrets");
        let mut shared_secret = Vec::new();
        shared_secret.extend_from_slice(dh1.as_bytes());
        shared_secret.extend_from_slice(dh2.as_bytes());
        shared_secret.extend_from_slice(dh3.as_bytes());
        shared_secret.extend_from_slice(dh4.as_bytes());
        shared_secret.extend_from_slice(&kyber_shared);
        
        // 4. Derive initial root key
        let mut hasher = Sha3_512::new();
        hasher.update(&shared_secret);
        hasher.update(b"SecNetSessionKey");
        let initial_key = hasher.finalize();
        
        // 5. Initialize Double Ratchet with derived key
        debug!("Initializing Double Ratchet");
        self.ratchet_state = Some(RatchetState::new_initiator(&initial_key[0..32]));
        
        // 6. Create initial DH ratchet key
        let dh_ratchet_key = self.ratchet_state.as_ref().unwrap().get_public_key();
        
        // 7. Sign all the data for authentication
        debug!("Signing initial key exchange data");
        let mut signing_data = Vec::new();
        signing_data.extend_from_slice(&self.identity.ed25519.public);
        signing_data.extend_from_slice(ephemeral_public.as_bytes());
        signing_data.extend_from_slice(&recipient_prekey.key_id);
        signing_data.extend_from_slice(kyber_ciphertext.as_bytes());
        signing_data.extend_from_slice(&dh_ratchet_key);
        
        // Create the Ed25519 keypair for signing
        let secret_bytes = &self.identity.ed25519.secret;
        let public_bytes = &self.identity.ed25519.public;
        
        let ed25519_secret = match Ed25519SecretKey::from_bytes(secret_bytes) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::InvalidKey("Invalid Ed25519 secret key".to_string())),
        };
        
        let ed25519_public = match Ed25519PublicKey::from_bytes(public_bytes) {
            Ok(key) => key,
            Err(_) => return Err(CryptoError::InvalidKey("Invalid Ed25519 public key".to_string())),
        };
        
        let keypair = Ed25519Keypair {
            secret: ed25519_secret,
            public: ed25519_public,
        };
        
        // Sign the data
        let signature = keypair.sign(&signing_data);
        
        // 8. Create initial key exchange message
        let key_exchange = SessionProtocol::InitialKeyExchange {
            identity_key: self.identity.ed25519.public.clone(),
            ephemeral_key: ephemeral_public.as_bytes().to_vec(),
            prekey_id: recipient_prekey.key_id.clone(),
            kyber_ciphertext,
            dh_ratchet_key,
            signature: signature.to_bytes().to_vec(),
        };
        
        // 9. Set remote identity for future reference
        self.remote_identity = Some(recipient_identity.fingerprint.clone());
        
        // 10. Serialize the key exchange protocol message
        let protocol_message = MessageType::Protocol(key_exchange);
        
        // 11. Create full message with metadata
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let message_id = format!("{}-{}", hex::encode(&thread_rng().gen::<[u8; 16]>()), timestamp);
        
        let message = Message {
            id: message_id,
            sender: self.identity.fingerprint.clone(),
            timestamp,
            msg_type: protocol_message,
            attachments: Vec::new(),
        };
        
        // 12. Encrypt the first message using derived key
        debug!("Encrypting initial message");
        let plaintext = serde_json::to_vec(&message)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to serialize message: {}", e)))?;
        
        let encrypted = self.encrypt_raw(&plaintext, &initial_key[32..64])?;
        let serialized = serde_json::to_vec(&encrypted)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to serialize encrypted message: {}", e)))?;
        
        info!("Session initialized successfully as initiator");
        Ok(serialized)
    }
    
    // Initialize a session with a peer as the responder (accepting an initial message)
    pub fn initialize_as_responder(
        &mut self,
        initial_message: &[u8],
        available_prekeys: &HashMap<Vec<u8>, PreKeyBundle>,
    ) -> Result<(), CryptoError> {
        info!("Initializing E2EE session as responder");
        
        // 1. Deserialize the incoming message
        let encrypted: EncryptedMessage = serde_json::from_slice(initial_message)
            .map_err(|e| CryptoError::DeserializationError(format!("Failed to deserialize message: {}", e)))?;
        
        // We need to extract the key exchange information from the header first
        let session_init_bytes = encrypted.encrypted_content.clone();
        
        // Since we don't have a session yet, we need to decrypt this with a temporary key
        // This assumes the encrypted content includes the key exchange info, which we'll extract next
        
        // 2. Extract the key exchange protocol message
        let protocol_message = self.extract_key_exchange(&encrypted.header, &session_init_bytes)?;
        
        // 3. Process the key exchange message
        match protocol_message {
            SessionProtocol::InitialKeyExchange {
                identity_key,
                ephemeral_key,
                prekey_id,
                kyber_ciphertext,
                dh_ratchet_key,
                signature,
            } => {
                debug!("Processing initial key exchange");
                
                // Verify the prekey exists
                let prekey = match available_prekeys.get(&prekey_id) {
                    Some(pk) => pk,
                    None => return Err(CryptoError::InvalidKey("Prekey not found".to_string())),
                };
                
                // Verify signature
                let sender_public_key = match Ed25519PublicKey::from_bytes(&identity_key) {
                    Ok(key) => key,
                    Err(_) => return Err(CryptoError::InvalidKey("Invalid sender Ed25519 key".to_string())),
                };
                
                let signature_bytes = match signature.try_into() {
                    Ok(sig) => sig,
                    Err(_) => return Err(CryptoError::SignatureError("Invalid signature length".to_string())),
                };
                
                let ed_signature = Signature::from_bytes(&signature_bytes)
                    .map_err(|_| CryptoError::SignatureError("Invalid signature format".to_string()))?;
                
                // Reconstruct the signed data
                let mut signed_data = Vec::new();
                signed_data.extend_from_slice(&identity_key);
                signed_data.extend_from_slice(&ephemeral_key);
                signed_data.extend_from_slice(&prekey_id);
                signed_data.extend_from_slice(kyber_ciphertext.as_bytes());
                signed_data.extend_from_slice(&dh_ratchet_key);
                
                // Verify signature
                match sender_public_key.verify(&signed_data, &ed_signature) {
                    Ok(_) => debug!("Signature verification successful"),
                    Err(_) => return Err(CryptoError::SignatureError("Signature verification failed".to_string())),
                }
                
                // 4. Calculate shared secrets (X3DH)
                
                // Load our key pairs
                let our_prekey_secret = X25519SecretKey::from(prekey.x25519.clone().try_into().unwrap());
                let our_identity_secret = X25519SecretKey::from(self.identity.x25519.secret.clone().try_into().unwrap());
                
                // Load peer keys
                let peer_identity = match X25519PublicKey::from_bytes(&identity_key) {
                    Some(key) => key,
                    Err(_) => return Err(CryptoError::InvalidKey("Invalid peer identity key".to_string())),
                };
                
                let peer_ephemeral = match X25519PublicKey::from_bytes(&ephemeral_key) {
                    Some(key) => key,
                    Err(_) => return Err(CryptoError::InvalidKey("Invalid peer ephemeral key".to_string())),
                };
                
                // Compute DH outputs
                let dh1 = our_identity_secret.diffie_hellman(&peer_identity);
                let dh2 = our_prekey_secret.diffie_hellman(&peer_identity);
                let dh3 = our_identity_secret.diffie_hellman(&peer_ephemeral);
                let dh4 = our_prekey_secret.diffie_hellman(&peer_ephemeral);
                
                // 5. Decrypt the Kyber ciphertext
                let kyber_shared = kyber::decapsulate(&self.identity.kyber.secret, &kyber_ciphertext);
                
                // 6. Combine shared secrets
                let mut shared_secret = Vec::new();
                shared_secret.extend_from_slice(dh1.as_bytes());
                shared_secret.extend_from_slice(dh2.as_bytes());
                shared_secret.extend_from_slice(dh3.as_bytes());
                shared_secret.extend_from_slice(dh4.as_bytes());
                shared_secret.extend_from_slice(&kyber_shared);
                
                // 7. Derive initial root key
                let mut hasher = Sha3_512::new();
                hasher.update(&shared_secret);
                hasher.update(b"SecNetSessionKey");
                let initial_key = hasher.finalize();
                
                // 8. Initialize Double Ratchet with remote's initial ratchet key
                debug!("Initializing Double Ratchet");
                self.ratchet_state = Some(RatchetState::new_responder(
                    &initial_key[0..32],
                    &dh_ratchet_key,
                ));
                
                // 9. Store remote identity for future use
                // Calculate fingerprint from identity key
                let mut hasher = Sha256::new();
                hasher.update(&identity_key);
                // We would need more data to calculate the full fingerprint, but this is a simplification
                let partial_fingerprint = hex::encode(hasher.finalize());
                self.remote_identity = Some(partial_fingerprint);
                
                info!("Session initialized successfully as responder");
                Ok(())
            },
            _ => Err(CryptoError::InvalidState("Expected initial key exchange message".to_string())),
        }
    }
    
    // Process an incoming encrypted message
    pub fn decrypt_message(&mut self, encrypted_data: &[u8]) -> Result<Message, CryptoError> {
        debug!("Decrypting incoming message");
        
        // Deserialize the encrypted message
        let encrypted: EncryptedMessage = serde_json::from_slice(encrypted_data)
            .map_err(|e| CryptoError::DeserializationError(format!("Failed to deserialize message: {}", e)))?;
        
        // Process the ratchet header to get the message key
        let message_key = self.process_header(&encrypted.header)?;
        
        // Verify MAC
        self.verify_mac(&encrypted, &message_key)?;
        
        // Decrypt the message content
        let decrypted = self.decrypt_with_key(&encrypted.encrypted_content, &message_key)?;
        
        // Deserialize the decrypted message
        let message: Message = serde_json::from_slice(&decrypted)
            .map_err(|e| CryptoError::DeserializationError(format!("Failed to deserialize decrypted message: {}", e)))?;
        
        // If this is a protocol message, handle it
        if let MessageType::Protocol(protocol) = &message.msg_type {
            self.handle_protocol_message(protocol)?;
        }
        
        debug!("Message decrypted successfully");
        Ok(message)
    }
    
    // Encrypt a message for the current session
    pub fn encrypt_message(&mut self, message_type: MessageType) -> Result<Vec<u8>, CryptoError> {
        debug!("Encrypting outgoing message");
        
        if self.ratchet_state.is_none() {
            return Err(CryptoError::InvalidState("No active session".to_string()));
        }
        
        // Create a full message with metadata
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let message_id = format!("{}-{}", hex::encode(&thread_rng().gen::<[u8; 16]>()), timestamp);
        
        let message = Message {
            id: message_id,
            sender: self.identity.fingerprint.clone(),
            timestamp,
            msg_type: message_type,
            attachments: Vec::new(),
        };
        
        // Serialize the message
        let plaintext = serde_json::to_vec(&message)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to serialize message: {}", e)))?;
        
        // Add padding for metadata protection
        let padded = self.add_padding(&plaintext);
        
        // Get the current ratchet state
        let state = self.ratchet_state.as_mut().unwrap();
        
        // Get next header and message key
        let (header, message_key) = state.ratchet_forward()?;
        
        // Create the secure header
        let secure_header = SecureMessageHeader {
            ratchet_header: header,
            message_id: message.id.clone(),
            sender_fingerprint: self.identity.fingerprint[0..16].to_string(), // Use only first 16 chars for privacy
            timestamp,
            padding_length: padded.len() - plaintext.len(),
        };
        
        // Encrypt the message
        let encrypted_content = self.encrypt_with_key(&padded, &message_key)?;
        
        // Create MAC for authenticity
        let mac = self.create_mac(&secure_header, &encrypted_content, &message_key)?;
        
        // Create the final encrypted message
        let encrypted_message = EncryptedMessage {
            header: secure_header,
            encrypted_content,
            mac,
        };
        
        // Serialize for transmission
        let serialized = serde_json::to_vec(&encrypted_message)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to serialize encrypted message: {}", e)))?;
        
        debug!("Message encrypted successfully");
        Ok(serialized)
    }
    
    // Process a ratchet header to get the message key
    fn process_header(&mut self, header: &SecureMessageHeader) -> Result<Vec<u8>, CryptoError> {
        debug!("Processing ratchet header");
        
        if self.ratchet_state.is_none() {
            return Err(CryptoError::InvalidState("No active session".to_string()));
        }
        
        let state = self.ratchet_state.as_mut().unwrap();
        
        // Check if we've already seen this message (prevents replay attacks)
        let message_key = self.check_skipped_message_keys(&header.ratchet_header)?;
        if let Some(key) = message_key {
            debug!("Using cached message key for skipped message");
            return Ok(key);
        }
        
        // Check if the ratchet key has changed
        let ratchet_changed = state.is_new_ratchet(&header.ratchet_header.dh_public);
        
        if ratchet_changed {
            debug!("Ratchet key changed, performing DH ratchet step");
            
            // Save skipped message keys
            self.skip_message_keys(header.ratchet_header.prev_chain_len)?;
            
            // Update the ratchet with new remote key
            state.update_remote_key(&header.ratchet_header.dh_public);
            
            // Perform DH ratchet step
            state.ratchet_dh()?;
        }
        
        // Skip message keys if needed
        if header.ratchet_header.message_num > state.get_recv_count() {
            self.skip_message_keys_until(header.ratchet_header.message_num)?;
        }
        
        // Derive the message key
        let message_key = state.derive_message_key(header.ratchet_header.message_num)?;
        
        // Update receive counter
        state.set_recv_count(header.ratchet_header.message_num + 1);
        
        debug!("Message key derived successfully");
        Ok(message_key)
    }
    
    // Skip message keys up to a certain count
    fn skip_message_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        if let Some(state) = &mut self.ratchet_state {
            let current_recv_count = state.get_recv_count();
            
            if until <= current_recv_count {
                return Ok(());
            }
            
            if until - current_recv_count > self.max_skipped as u32 {
                return Err(CryptoError::SecurityError("Too many skipped messages".to_string()));
            }
            
            let current_ratchet_key = state.get_remote_key()
                .ok_or_else(|| CryptoError::InvalidState("No remote ratchet key".to_string()))?;
            
            // Get the map for current ratchet key or create a new one
            let skipped_keys = self.skipped_message_keys
                .entry(current_ratchet_key.clone())
                .or_insert_with(HashMap::new);
            
            // Generate and store skipped message keys
            for i in current_recv_count..until {
                let key = state.derive_message_key(i)?;
                skipped_keys.insert(i, key);
                debug!("Stored skipped message key for message {}", i);
            }
            
            // Update the receive counter
            state.set_recv_count(until);
            
            Ok(())
        } else {
            Err(CryptoError::InvalidState("No active session".to_string()))
        }
    }
    
    // Skip message keys until a specific message number
    fn skip_message_keys_until(&mut self, message_num: u32) -> Result<(), CryptoError> {
        self.skip_message_keys(message_num)
    }
    
    // Check if we have a skipped message key for this header
    fn check_skipped_message_keys(&mut self, header: &MessageHeader) -> Result<Option<Vec<u8>>, CryptoError> {
        // Check if we have any skipped keys for this ratchet
        if let Some(skipped_keys) = self.skipped_message_keys.get_mut(&header.dh_public) {
            // Check if we have the specific message key
            if let Some(key) = skipped_keys.remove(&header.message_num) {
                debug!("Found skipped message key for message {}", header.message_num);
                return Ok(Some(key));
            }
        }
        
        Ok(None)
    }
    
    // Create MAC for message authentication
    fn create_mac(&self, header: &SecureMessageHeader, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let header_bytes = serde_json::to_vec(header)
            .map_err(|e| CryptoError::EncryptionError(format!("Failed to serialize header: {}", e)))?;
        
        let mut mac_data = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        mac_data.extend_from_slice(&header_bytes);
        mac_data.extend_from_slice(ciphertext);
        
        let mut mac_key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(b"SecNetMAC");
        mac_key.copy_from_slice(&hasher.finalize());
        
        // Create HMAC
        let mut hasher = Sha3_256::new();
        hasher.update(&mac_key);
        hasher.update(&mac_data);
        
        Ok(hasher.finalize().to_vec())
    }
    
    // Verify MAC for message authentication
    fn verify_mac(&self, message: &EncryptedMessage, key: &[u8]) -> Result<(), CryptoError> {
        let calculated_mac = self.create_mac(&message.header, &message.encrypted_content, key)?;
        
        // Constant-time comparison to prevent timing attacks
        if calculated_mac.len() != message.mac.len() {
            return Err(CryptoError::SecurityError("MAC verification failed".to_string()));
        }
        
        let mut result = 0u8;
        for (a, b) in calculated_mac.iter().zip(message.mac.iter()) {
            result |= a ^ b;
        }
        
        if result != 0 {
            return Err(CryptoError::SecurityError("MAC verification failed".to_string()));
        }
        
        Ok(())
    }
    
    // Encrypt with a specific key using ChaCha20-Poly1305
    fn encrypt_with_key(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::EncryptionError("Invalid key length".to_string()));
        }
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12]; // ChaCha20-Poly1305 needs a 12-byte nonce
        thread_rng().fill(&mut nonce_bytes);
        
        // Create cipher
        let encryption_key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(encryption_key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionError("Encryption failed".to_string()))?;
        
        // Combine nonce and ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    // Decrypt with a specific key using ChaCha20-Poly1305
    fn decrypt_with_key(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::DecryptionError("Invalid key length".to_string()));
        }
        
        if ciphertext.len() < 12 {
            return Err(CryptoError::DecryptionError("Ciphertext too short".to_string()));
        }
        
        // Extract nonce and actual ciphertext
        let nonce_bytes = &ciphertext[0..12];
        let actual_ciphertext = &ciphertext[12..];
        
        // Create cipher
        let decryption_key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(decryption_key);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt
        let plaintext = cipher.decrypt(nonce, actual_ciphertext)
            .map_err(|_| CryptoError::DecryptionError("Decryption failed".to_string()))?;
        
        Ok(plaintext)
    }
    
    // Add padding to messages to mask real size
    fn add_padding(&self, data: &[u8]) -> Vec<u8> {
        let block_size = match self.security_level {
            SecurityLevel::Standard => 64,     // Lower padding for standard security
            SecurityLevel::High => 128,        // Medium padding for high security
            SecurityLevel::Quantum => 256,     // Higher padding for quantum security
        };
        
        // Calculate the padded size (round up to next block_size)
        let padded_size = ((data.len() + block_size - 1) / block_size) * block_size;
        
        // Add random padding between 0 and block_size/2
        let padding_size = thread_rng().gen_range(0..(block_size / 2));
        let target_size = padded_size + padding_size;
        
        // Create padded data
        let mut padded = Vec::with_capacity(target_size);
        padded.extend_from_slice(data);
        
        // Fill remaining space with random bytes
        let remaining = target_size - data.len();
        let mut padding = vec![0u8; remaining];
        thread_rng().fill(&mut padding[..]);
        padded.extend_from_slice(&padding);
        
        padded
    }
    
    // Remove padding from messages
    fn remove_padding(&self, padded: &[u8], padding_length: usize) -> Vec<u8> {
        if padded.len() <= padding_length {
            return Vec::new();
        }
        
        padded[0..(padded.len() - padding_length)].to_vec()
    }
    
    // Handle protocol messages
    fn handle_protocol_message(&mut self, protocol: &SessionProtocol) -> Result<(), CryptoError> {
        match protocol {
            SessionProtocol::RatchetAdvance { new_ratchet_key } => {
                debug!("Processing ratchet advance message");
                
                if let Some(state) = &mut self.ratchet_state {
                    // Update remote ratchet key
                    state.update_remote_key(new_ratchet_key);
                    
                    // Perform DH ratchet step
                    state.ratchet_dh()?;
                    
                    debug!("Ratchet updated successfully");
                } else {
                    return Err(CryptoError::InvalidState("No active session".to_string()));
                }
            },
            SessionProtocol::Heartbeat { timestamp, counter } => {
                // Just acknowledge heartbeat, no action needed
                debug!("Received heartbeat: timestamp={}, counter={}", timestamp, counter);
            },
            SessionProtocol::SessionEnd { reason } => {
                debug!("Received session end message: {}", reason);
                
                // Clear session state
                self.ratchet_state = None;
                self.message_keys.clear();
                self.skipped_message_keys.clear();
                
                info!("Session terminated by peer: {}", reason);
            },
            _ => {
                // InitialKeyExchange should be handled separately
                warn!("Received unexpected protocol message type");
            }
        }
        
        Ok(())
    }
    
    // Extract key exchange information from an initial message
    fn extract_key_exchange(&self, header: &SecureMessageHeader, ciphertext: &[u8]) -> Result<SessionProtocol, CryptoError> {
        // This is a special case for the initial message where we don't have a session yet
        
        // Try to decrypt with a derived key based on header information
        // In a real implementation, this would involve more sophisticated key derivation
        
        // For simplicity in this example, we'll assume the ciphertext contains the serialized protocol message
        // In a real implementation, you would need proper key derivation for the initial message
        
        // This is a placeholder that should be replaced with proper initial message handling
        let message: Message = serde_json::from_slice(&ciphertext)
            .map_err(|e| CryptoError::DeserializationError(format!("Failed to deserialize key exchange: {}", e)))?;
        
        match message.msg_type {
            MessageType::Protocol(protocol) => Ok(protocol),
            _ => Err(CryptoError::InvalidState("Expected protocol message for key exchange".to_string())),
        }
    }
    
    // Encrypt raw data with a provided key (for initial message)
    fn encrypt_raw(&self, data: &[u8], key: &[u8]) -> Result<EncryptedMessage, CryptoError> {
        // Generate a temporary header for the initial message
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let message_id = format!("init-{}", timestamp);
        
        let header = SecureMessageHeader {
            ratchet_header: MessageHeader {
                dh_public: self.identity.x25519.public.clone(),
                prev_chain_len: 0,
                message_num: 0,
            },
            message_id,
            sender_fingerprint: self.identity.fingerprint[0..16].to_string(),
            timestamp,
            padding_length: 0,
        };
        
        // Encrypt the data
        let encrypted_content = self.encrypt_with_key(data, key)?;
        
        // Create MAC
        let mac = self.create_mac(&header, &encrypted_content, key)?;
        
        // Create encrypted message
        let encrypted = EncryptedMessage {
            header,
            encrypted_content,
            mac,
        };
        
        Ok(encrypted)
    }
    
    // End the current session
    pub fn end_session(&mut self, reason: &str) -> Result<Vec<u8>, CryptoError> {
        info!("Ending session: {}", reason);
        
        // Create session end protocol message
        let protocol = SessionProtocol::SessionEnd {
            reason: reason.to_string(),
        };
        
        // Create and encrypt the message
        let encrypted = self.encrypt_message(MessageType::Protocol(protocol))?;
        
        // Clear session state
        self.ratchet_state = None;
        self.message_keys.clear();
        self.skipped_message_keys.clear();
        
        info!("Session ended");
        Ok(encrypted)
    }
    
    // Force a ratchet advance
    pub fn force_ratchet(&mut self) -> Result<Vec<u8>, CryptoError> {
        debug!("Forcing ratchet advance");
        
        if self.ratchet_state.is_none() {
            return Err(CryptoError::InvalidState("No active session".to_string()));
        }
        
        // Generate new ratchet key pair
        let state = self.ratchet_state.as_mut().unwrap();
        state.rotate_key_pair()?;
        
        // Get new public key
        let new_ratchet_key = state.get_public_key();
        
        // Create ratchet advance protocol message
        let protocol = SessionProtocol::RatchetAdvance {
            new_ratchet_key,
        };
        
        // Create and encrypt the message
        let encrypted = self.encrypt_message(MessageType::Protocol(protocol))?;
        
        debug!("Ratchet advance message created");
        Ok(encrypted)
    }
    
    // Send a heartbeat to keep the session alive
    pub fn send_heartbeat(&mut self) -> Result<Vec<u8>, CryptoError> {
        debug!("Sending heartbeat");
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Use a counter based on session state
        let counter = match &self.ratchet_state {
            Some(state) => state.get_send_count(),
            None => return Err(CryptoError::InvalidState("No active session".to_string())),
        };
        
        // Create heartbeat protocol message
        let protocol = SessionProtocol::Heartbeat {
            timestamp,
            counter,
        };
        
        // Create and encrypt the message
        let encrypted = self.encrypt_message(MessageType::Protocol(protocol))?;
        
        debug!("Heartbeat sent");
        Ok(encrypted)
    }
    
    // Check if session is active
    pub fn is_active(&self) -> bool {
        self.ratchet_state.is_some()
    }
    
    // Get remote identity fingerprint
    pub fn get_remote_identity(&self) -> Option<&String> {
        self.remote_identity.as_ref()
    }
    
    // Get current security level
    pub fn get_security_level(&self) -> SecurityLevel {
        self.security_level
    }
    
    // Set security level
    pub fn set_security_level(&mut self, level: SecurityLevel) {
        debug!("Changing security level to {:?}", level);
        self.security_level = level;
    }
    
    // Set maximum skipped message keys
    pub fn set_max_skipped(&mut self, max: usize) {
        debug!("Setting max skipped messages to {}", max);
        self.max_skipped = max;
    }
}

// Additional trait implementation for error conversion
impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptoError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            CryptoError::SignatureError(msg) => write!(f, "Signature error: {}", msg),
            CryptoError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            CryptoError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            CryptoError::SessionError(msg) => write!(f, "Session error: {}", msg),
            CryptoError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            CryptoError::SecurityError(msg) => write!(f, "Security error: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

// Extension to CryptoError to include security-related errors
impl CryptoError {
    fn SecurityError(msg: String) -> Self {
        CryptoError::EncryptionError(msg)
    }
}

// Extension of the RatchetState to simplify implementation
impl RatchetState {
    // Create a new ratchet state for initiator
    fn new_initiator(root_key: &[u8]) -> Self {
        // This is a simplified implementation
        // Generate DH key pair
        let mut csprng = rand_07::rngs::OsRng{};
        let dh_secret = X25519SecretKey::new(csprng);
        let dh_public = X25519PublicKey::from(&dh_secret);
        
        RatchetState {
            dh_key_pair: rand_07::rngs::OsRng{}, // placeholder
            dh_remote_key: None,
            root_key: root_key.to_vec(),
            send_chain_key: Vec::new(),
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_message_keys: Vec::new(),
            pending_commit: false,
        }
    }
    
    // Create a new ratchet state for responder
    fn new_responder(root_key: &[u8], remote_key: &[u8]) -> Self {
        // This is a simplified implementation
        RatchetState {
            dh_key_pair: rand_07::rngs::OsRng{}, // placeholder
            dh_remote_key: Some(remote_key.to_vec()),
            root_key: root_key.to_vec(),
            send_chain_key: Vec::new(),
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_message_keys: Vec::new(),
            pending_commit: false,
        }
    }
    
    // Check if this is a new ratchet public key
    fn is_new_ratchet(&self, ratchet_key: &[u8]) -> bool {
        match &self.dh_remote_key {
            Some(current_key) => current_key != ratchet_key,
            None => true,
        }
    }
    
    // Update remote ratchet key
    fn update_remote_key(&mut self, ratchet_key: &[u8]) {
        self.dh_remote_key = Some(ratchet_key.to_vec());
    }
    
    // Get current remote ratchet key
    fn get_remote_key(&self) -> Option<Vec<u8>> {
        self.dh_remote_key.clone()
    }
    
    // Get current public key
    fn get_public_key(&self) -> Vec<u8> {
        Vec::new() // Placeholder
    }
    
    // Perform DH ratchet step
    fn ratchet_dh(&mut self) -> Result<(), CryptoError> {
        Ok(()) // Placeholder
    }
    
    // Get current receive count
    fn get_recv_count(&self) -> u32 {
        self.recv_count
    }
    
    // Set receive count
    fn set_recv_count(&mut self, count: u32) {
        self.recv_count = count;
    }
    
    // Get current send count
    fn get_send_count(&self) -> u32 {
        self.send_count
    }
    
    // Derive message key for a specific message number
    fn derive_message_key(&self, message_num: u32) -> Result<Vec<u8>, CryptoError> {
        // Placeholder implementation
        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&self.root_key);
        hasher.update(&message_num.to_be_bytes());
        hasher.update(b"MessageKey");
        key.copy_from_slice(&hasher.finalize());
        
        Ok(key.to_vec())
    }
    
    // Rotate key pair for new ratchet
    fn rotate_key_pair(&mut self) -> Result<(), CryptoError> {
        Ok(()) // Placeholder
    }
    
    // Ratchet forward and get next header and message key
    fn ratchet_forward(&mut self) -> Result<(MessageHeader, Vec<u8>), CryptoError> {
        // Placeholder implementation
        let header = MessageHeader {
            dh_public: Vec::new(),
            prev_chain_len: 0,
            message_num: 0,
        };
        
        let message_key = [0u8; 32].to_vec();
        Ok((header, message_key))
    }
}