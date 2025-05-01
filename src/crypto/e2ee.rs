// src/crypto/e2ee.rs
// Implementation of an end-to-end encryption protocol
// Combining Double Ratchet, X25519, and Kyber for post-quantum security

use ed25519_dalek::{Signature, Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey};
use log::{debug, error, info, trace, warn};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha3_256, Sha3_512};
use std::convert::TryInto;
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
        parameters: std::collections::HashMap<String, String>,
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
    message_keys: std::collections::HashMap<u32, Vec<u8>>, // Message number -> key
    security_level: SecurityLevel,
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
            message_keys: std::collections::HashMap::new(),
            security_level,
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
        signing_data.extend_from_slice(&