// src/crypto/ratchet.rs
//
// This module implements the Double Ratchet Algorithm based on the Signal Protocol
// specification for forward secrecy and post-compromise security.
// https://signal.org/docs/specifications/doubleratchet/
//
// The Double Ratchet Algorithm combines the Diffie-Hellman key exchange with a
// symmetric-key ratchet to provide strong forward secrecy and recovery from compromise.

use log::{debug, error, trace};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub dh_key_pair: DHKeyPair,  // Current ratchet key pair
    pub dh_remote_key: Option<Vec<u8>>,  // Remote ratchet key
    pub root_key: Vec<u8>,        // Current root key (32 bytes)
    pub send_chain_key: Vec<u8>,  // Current sending chain key (32 bytes)
    pub recv_chain_key: Option<Vec<u8>>,  // Current receiving chain key (32 bytes)
    pub send_count: u32,          // Number of messages sent with current sending chain
    pub recv_count: u32,          // Number of messages received with current receiving chain
    pub prev_send_count: u32,     // Number of messages sent with previous sending chain
    pub skipped_message_keys: Vec<SkippedMessageKey>, // Message keys for skipped messages
    pub pending_commit: bool,     // Flag indicating a ratchet step is needed on next send
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DHKeyPair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkippedMessageKey {
    pub dh_public: Vec<u8>,       // Ephemeral public key used for this message
    pub message_number: u32,      // Message number in the chain
    pub message_key: Vec<u8>,     // Derived message key
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    pub dh_public: Vec<u8>,       // Sender's current ratchet public key
    pub prev_chain_len: u32,      // Previous chain length 
    pub message_num: u32,         // Message number in current chain
}

#[derive(Debug)]
pub enum RatchetError {
    InvalidKey,
    InvalidState,
    InvalidHeader,
    DecryptionFailed,
    EncryptionFailed,
}

impl RatchetState {
    /// Create a new RatchetState for initializing a session
    pub fn new(
        shared_secret: &[u8],
        is_initiator: bool,
        remote_public_key: Option<&[u8]>
    ) -> Result<Self, RatchetError> {
        // Generate DH keypair
        let csprng = rand_07::rngs::OsRng{};
        let dh_secret = X25519SecretKey::new(csprng);
        let dh_public = X25519PublicKey::from(&dh_secret);
        
        let dh_key_pair = DHKeyPair {
            private: dh_secret.to_bytes().to_vec(),
            public: dh_public.as_bytes().to_vec(),
        };
        
        // Generate initial root key with HKDF
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(b"SecNetRootKey");
        let root_key = hasher.finalize().to_vec();
        
        // Generate initial chain keys
        let (send_chain_key, recv_chain_key) = if is_initiator {
            // For initiator: use DH output as first chain key
            let send_key = derive_initial_chain_key(&root_key, b"sending");
            let recv_key = derive_initial_chain_key(&root_key, b"receiving");
            (send_key, Some(recv_key))
        } else {
            // For responder: wait for first message to derive chain keys
            let send_key = derive_initial_chain_key(&root_key, b"sending");
            (send_key, None)
        };
        
        Ok(RatchetState {
            dh_key_pair,
            dh_remote_key: remote_public_key.map(|k| k.to_vec()),
            root_key,
            send_chain_key,
            recv_chain_key,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_message_keys: Vec::new(),
            pending_commit: false,
        })
    }
    
    /// Ratchet the local state forward using DH with remote key
    pub fn ratchet_dh(&mut self) -> Result<(), RatchetError> {
        debug!("Performing Double Ratchet step");
        
        // Ensure we have a remote key
        let remote_key = match &self.dh_remote_key {
            Some(key) => key.clone(),
            None => {
                error!("Cannot ratchet: no remote key available");
                return Err(RatchetError::InvalidState);
            }
        };
        
        // Convert keys to X25519 format
        let dh_secret = match X25519SecretKey::from_bytes(&self.dh_key_pair.private) {
            Some(key) => key,
            None => {
                error!("Invalid DH secret key");
                return Err(RatchetError::InvalidKey);
            }
        };
        
        let mut public_bytes = [0u8; 32];
        if remote_key.len() >= 32 {
            public_bytes.copy_from_slice(&remote_key[0..32]);
            let remote_public = X25519PublicKey::from(public_bytes);
            // Continue with the code
        } else {
            error!("Invalid remote public key");
            return Err(RatchetError::InvalidKey);
        }
        
        // Compute Diffie-Hellman shared secret
        let dh_output = dh_secret.diffie_hellman(&remote_public);
        
        // Generate new DH key pair
        let csprng = rand_07::rngs::OsRng{};
        let new_dh_secret = X25519SecretKey::new(csprng);
        let new_dh_public = X25519PublicKey::from(&new_dh_secret);
        
        // Update state for new chain
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        
        // Calculate new keys with KDF
        let (new_root_key, new_chain_key) = kdf_rk(
            &self.root_key,
            dh_output.as_bytes()
        );
        
        // Update state
        self.root_key = new_root_key;
        self.send_chain_key = new_chain_key;
        self.dh_key_pair = DHKeyPair {
            private: new_dh_secret.to_bytes().to_vec(),
            public: new_dh_public.as_bytes().to_vec(),
        };
        self.pending_commit = false;
        
        debug!("Double Ratchet step completed successfully");
        Ok(())
    }
    
    /// Process received header and prepare decryption
    pub fn process_header(&mut self, header: &MessageHeader) -> Result<Vec<u8>, RatchetError> {
        // Check if the remote key has changed
        let remote_key_changed = match &self.dh_remote_key {
            Some(current_key) => !constant_time_eq(current_key, &header.dh_public),
            None => true,
        };
        
        // Store current remote public key for use in decrypt
        let _current_remote_key = self.dh_remote_key.clone();
        
        // If remote key changed, we need to perform a Double Ratchet step
        if remote_key_changed {
            debug!("Remote ratchet key changed, triggering DH ratchet");
            
            // Save any skipped message keys from the previous chain
            self.skip_message_keys(header.prev_chain_len)?;
            
            // Update remote key
            self.dh_remote_key = Some(header.dh_public.clone());
            
            // If this is our first received message, initialize receiving chain key
            if self.recv_chain_key.is_none() {
                self.initialize_recv_chain()?;
            } else {
                // Ratchet forward with the new remote key
                self.ratchet_dh()?;
            }
            
            // Reset receive count for new chain
            self.recv_count = 0;
        }
        
        // Skip message keys if needed
        self.skip_message_keys(header.message_num)?;
        
        // Try to find a skipped message key first
        for (i, skipped) in self.skipped_message_keys.iter().enumerate() {
            if constant_time_eq(&skipped.dh_public, &header.dh_public) && 
               skipped.message_number == header.message_num {
                // Found a matching skipped key, use it and remove it
                let message_key = skipped.message_key.clone();
                self.skipped_message_keys.remove(i);
                return Ok(message_key);
            }
        }
        
        // Derive message key from the chain
        let message_key = if let Some(chain_key) = &self.recv_chain_key {
            let (new_chain_key, message_key) = kdf_ck(chain_key, header.message_num);
            self.recv_chain_key = Some(new_chain_key);
            self.recv_count = header.message_num + 1;
            message_key
        } else {
            error!("No receiving chain key available");
            return Err(RatchetError::InvalidState);
        };
        
        Ok(message_key)
    }
    
    /// Skip message keys for missing messages and store them
    fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        if self.recv_chain_key.is_none() || until <= self.recv_count {
            return Ok(());
        }
        
        // Skip message keys up to the target
        let chain_key = self.recv_chain_key.as_ref().unwrap().clone();
        let current_remote_key = match &self.dh_remote_key {
            Some(key) => key.clone(),
            None => {
                error!("Cannot skip message keys: no remote key available");
                return Err(RatchetError::InvalidState);
            }
        };
        
        for i in self.recv_count..until {
            let (new_chain_key, message_key) = kdf_ck(&chain_key, i);
            
            self.skipped_message_keys.push(SkippedMessageKey {
                dh_public: current_remote_key.clone(),
                message_number: i,
                message_key,
            });
            
            self.recv_chain_key = Some(new_chain_key);
        }
        
        self.recv_count = until;
        Ok(())
    }
    
    /// Initialize the receiving chain (for first received message)
    fn initialize_recv_chain(&mut self) -> Result<(), RatchetError> {
        debug!("Initializing receiving chain for first message");
        
        let remote_key = match &self.dh_remote_key {
            Some(key) => key,
            None => {
                error!("Cannot initialize receive chain: no remote key");
                return Err(RatchetError::InvalidState);
            }
        };
        
        // Convert keys to X25519 format
        let mut secret_bytes = [0u8; 32];
        if self.dh_key_pair.private.len() >= 32 {
            secret_bytes.copy_from_slice(&self.dh_key_pair.private[0..32]);
            let dh_secret = X25519SecretKey::from(secret_bytes);
            // Continue with the code
        } else {
            error!("Invalid DH secret key");
            return Err(RatchetError::InvalidKey);
        }
        
        let remote_public = match X25519PublicKey::from_bytes(remote_key) {
            Some(key) => key,
            None => {
                error!("Invalid remote public key");
                return Err(RatchetError::InvalidKey);
            }
        };
        
        // Compute Diffie-Hellman shared secret
        let dh_output = dh_secret.diffie_hellman(&remote_public);
        
        // Calculate new root key and chain key
        let (new_root_key, new_chain_key) = kdf_rk(
            &self.root_key,
            dh_output.as_bytes()
        );
        
        // Update state
        self.root_key = new_root_key;
        self.recv_chain_key = Some(new_chain_key);
        
        debug!("Receive chain initialized successfully");
        Ok(())
    }
    
    /// Prepare header and message key for sending
    pub fn prepare_send(&mut self) -> Result<(MessageHeader, Vec<u8>), RatchetError> {
        // If pending commit, perform a DH ratchet step first
        if self.pending_commit {
            self.ratchet_dh()?;
        }
        
        // Create header
        let header = MessageHeader {
            dh_public: self.dh_key_pair.public.clone(),
            prev_chain_len: self.prev_send_count,
            message_num: self.send_count,
        };
        
        // Derive message key
        let (new_chain_key, message_key) = kdf_ck(&self.send_chain_key, self.send_count);
        self.send_chain_key = new_chain_key;
        self.send_count += 1;
        
        Ok((header, message_key))
    }
}

// Key Derivation Functions (KDF)

/// KDF for root key - derives a new root key and chain key from the current root key and DH output
fn kdf_rk(root_key: &[u8], dh_output: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Combine inputs
    let mut kdf_input = Vec::with_capacity(root_key.len() + dh_output.len());
    kdf_input.extend_from_slice(root_key);
    kdf_input.extend_from_slice(dh_output);
    
    // Derive new root key
    let mut hasher = Sha256::new();
    hasher.update(&kdf_input);
    hasher.update(b"RootKey");
    let new_root_key = hasher.finalize().to_vec();
    
    // Derive new chain key
    let mut hasher = Sha256::new();
    hasher.update(&new_root_key);
    hasher.update(b"ChainKey");
    let new_chain_key = hasher.finalize().to_vec();
    
    (new_root_key, new_chain_key)
}

/// KDF for chain key - derives next chain key and message key
fn kdf_ck(chain_key: &[u8], message_number: u32) -> (Vec<u8>, Vec<u8>) {
    let mut next_chain_key = chain_key.to_vec();
    let mut message_key = Vec::new();
    
    // Derive keys for each message number
    for i in 0..=message_number {
        // Derive message key
        let mut hasher = Sha256::new();
        hasher.update(&next_chain_key);
        hasher.update(b"MessageKey");
        hasher.update(&i.to_be_bytes());
        message_key = hasher.finalize().to_vec();
        
        // Derive next chain key
        let mut hasher = Sha256::new();
        hasher.update(&next_chain_key);
        hasher.update(b"NextChainKey");
        hasher.update(&i.to_be_bytes());
        next_chain_key = hasher.finalize().to_vec();
    }
    
    (next_chain_key, message_key)
}

/// Initial chain key derivation
fn derive_initial_chain_key(root_key: &[u8], purpose: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(root_key);
    hasher.update(purpose);
    hasher.finalize().to_vec()
}

/// Compare two byte slices in constant time to prevent timing attacks
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
    use rand::Rng;
    
    #[test]
    fn test_ratchet_initialization() {
        // Create a shared secret
        let shared_secret = [0u8; 32];
        
        // Initialize initiator and responder states
        let initiator_state = RatchetState::new(&shared_secret, true, None).unwrap();
        let responder_state = RatchetState::new(&shared_secret, false, Some(&initiator_state.dh_key_pair.public)).unwrap();
        
        assert!(initiator_state.recv_chain_key.is_some());
        assert!(responder_state.recv_chain_key.is_none());
    }
    
    #[test]
    fn test_message_key_derivation() {
        let chain_key = [0u8; 32];
        
        // Derive keys for consecutive messages
        let (chain_key1, message_key0) = kdf_ck(&chain_key, 0);
        let (chain_key2, message_key1) = kdf_ck(&chain_key1, 1);
        
        // Keys should be different
        assert_ne!(chain_key, chain_key1);
        assert_ne!(chain_key1, chain_key2);
        assert_ne!(message_key0, message_key1);
    }
    
    #[test]
    fn test_prepare_send_and_process_header() {
        // Create a shared secret
        let mut shared_secret = [0u8; 32];
        rand::thread_rng().fill(&mut shared_secret);
        
        // Initialize states
        let mut alice_state = RatchetState::new(&shared_secret, true, None).unwrap();
        
        // Send a message from Alice and process the header at Bob's side
        let (header, message_key_alice) = alice_state.prepare_send().unwrap();
        
        let mut bob_state = RatchetState::new(&shared_secret, false, Some(&header.dh_public)).unwrap();
        let message_key_bob = bob_state.process_header(&header).unwrap();
        
        // Both should derive the same message key
        assert_eq!(message_key_alice, message_key_bob);
    }
}