// src/crypto/keys.rs - Updated with proper Kyber implementation
use ed25519_dalek::Keypair as Ed25519Keypair;
use rand_07::rngs::OsRng as OsRng07; // Using rand 0.7 explicitly for ed25519-dalek compatibility
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use log::{debug, error, info, trace, warn};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

use crate::crypto::kyber::{self, KyberKeypair, KyberPublicKey, KyberSecretKey, KyberCiphertext};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityKeyBundle {
    pub ed25519: IdentityEd25519,
    pub x25519: IdentityX25519,
    pub kyber: KyberKeypair,
    pub fingerprint: String,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityEd25519 {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityX25519 {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub key_id: Vec<u8>,
    pub x25519: Vec<u8>,
    pub kyber: KyberPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub remote_fingerprint: String,
    pub shared_secret: Vec<u8>,
    pub root_key: Vec<u8>,
    pub chain_key: Vec<u8>,
    pub message_counter: u32,
    pub prekey_id: Option<Vec<u8>>,
    pub ratchet_state: RatchetState,
}

// Added for Double Ratchet implementation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub dh_s: Vec<u8>,                // Current ratchet key (private)
    pub dh_r: Option<Vec<u8>>,        // Remote ratchet key (public)
    pub root_key: Vec<u8>,            // Current root key
    pub send_chain_key: Vec<u8>,      // Current sending chain key
    pub recv_chain_key: Option<Vec<u8>>, // Current receiving chain key
    pub send_count: u32,              // Number of messages sent
    pub recv_count: u32,              // Number of messages received
    pub prev_send_count: u32,         // Number of messages sent with previous sending chain
    pub ratchet_flag: bool,           // Flag indicating if we need to ratchet on next send
}

#[derive(Debug)]
pub enum KeyManagerError {
    IoError(std::io::Error),
    SerializationError(serde_json::Error),
    KeyGenerationError(String),
    KeyNotFound,
    InvalidKey,
    EncryptionError(String),
    DecryptionError(String),
}

impl fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyManagerError::IoError(e) => write!(f, "I/O error: {}", e),
            KeyManagerError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            KeyManagerError::KeyGenerationError(s) => write!(f, "Key generation error: {}", s),
            KeyManagerError::KeyNotFound => write!(f, "Key not found"),
            KeyManagerError::InvalidKey => write!(f, "Invalid key"),
            KeyManagerError::EncryptionError(s) => write!(f, "Encryption error: {}", s),
            KeyManagerError::DecryptionError(s) => write!(f, "Decryption error: {}", s),
        }
    }
}

impl StdError for KeyManagerError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            KeyManagerError::IoError(e) => Some(e),
            KeyManagerError::SerializationError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KeyManagerError {
    fn from(err: std::io::Error) -> Self {
        KeyManagerError::IoError(err)
    }
}

impl From<serde_json::Error> for KeyManagerError {
    fn from(err: serde_json::Error) -> Self {
        KeyManagerError::SerializationError(err)
    }
}

pub struct KeyManager {
    identity_keys: Option<IdentityKeyBundle>,
    peer_keys: HashMap<String, IdentityKeyBundle>,
    sessions: HashMap<String, Session>,
    prekeys: Vec<PreKeyBundle>,
    storage_path: String,
}

impl KeyManager {
    pub fn new(storage_path: &str) -> Result<Self, KeyManagerError> {
        info!("Initializing KeyManager with storage path: {}", storage_path);
        
        // Create directory if it doesn't exist
        if !Path::new(storage_path).exists() {
            debug!("Storage directory doesn't exist, creating: {}", storage_path);
            fs::create_dir_all(storage_path)?;
        }
        
        let identity_path = format!("{}/identity.json", storage_path);
        let peers_path = format!("{}/peers.json", storage_path);
        let sessions_path = format!("{}/sessions.json", storage_path);
        let prekeys_path = format!("{}/prekeys.json", storage_path);
        
        // Load identity if it exists
        let identity_keys = if Path::new(&identity_path).exists() {
            debug!("Loading identity from: {}", identity_path);
            let mut file = File::open(&identity_path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let identity: IdentityKeyBundle = serde_json::from_str(&contents)?;
            info!("Identity loaded successfully: {}", identity.fingerprint);
            Some(identity)
        } else {
            debug!("No identity file found at: {}", identity_path);
            None
        };
        
        // Load peers if they exist
        let peer_keys = if Path::new(&peers_path).exists() {
            debug!("Loading peers from: {}", peers_path);
            let mut file = File::open(&peers_path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let peers: HashMap<String, IdentityKeyBundle> = serde_json::from_str(&contents)?;
            info!("Loaded {} peers", peers.len());
            peers
        } else {
            debug!("No peers file found at: {}", peers_path);
            HashMap::new()
        };
        
        // Load sessions if they exist
        let sessions = if Path::new(&sessions_path).exists() {
            debug!("Loading sessions from: {}", sessions_path);
            let mut file = File::open(&sessions_path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let sessions: HashMap<String, Session> = serde_json::from_str(&contents)?;
            info!("Loaded {} sessions", sessions.len());
            sessions
        } else {
            debug!("No sessions file found at: {}", sessions_path);
            HashMap::new()
        };
        
        // Load prekeys if they exist
        let prekeys = if Path::new(&prekeys_path).exists() {
            debug!("Loading prekeys from: {}", prekeys_path);
            let mut file = File::open(&prekeys_path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let prekeys: Vec<PreKeyBundle> = serde_json::from_str(&contents)?;
            info!("Loaded {} prekeys", prekeys.len());
            prekeys
        } else {
            debug!("No prekeys file found at: {}", prekeys_path);
            Vec::new()
        };
        
        Ok(KeyManager {
            identity_keys,
            peer_keys,
            sessions,
            prekeys,
            storage_path: storage_path.to_string(),
        })
    }
    
    pub fn generate_identity_keys(&mut self, alias: Option<String>) -> Result<&IdentityKeyBundle, KeyManagerError> {
        info!("Generating new identity keys");
        
        // Generate Ed25519 keypair - using OsRng from rand 0.7 specifically for ed25519-dalek
        debug!("Generating Ed25519 keypair");
        let mut csprng = OsRng07{};
        let ed25519_keypair = Ed25519Keypair::generate(&mut csprng);
        
        // Generate X25519 keypair - using OsRng from rand 0.7
        debug!("Generating X25519 keypair");
        let x25519_secret = X25519SecretKey::new(csprng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        
        // Generate Kyber keypair
        debug!("Generating Kyber keypair");
        let mut rng = rand::thread_rng();
        let kyber_keypair = KyberKeypair::generate(&mut rng);
        
        // Calculate fingerprint (hash of all public keys)
        let mut hasher = Sha256::new();
        hasher.update(ed25519_keypair.public.as_bytes());
        hasher.update(x25519_public.as_bytes());
        hasher.update(kyber_keypair.public.as_bytes());
        let fingerprint = hex::encode(hasher.finalize());
        
        debug!("Generated key fingerprint: {}", fingerprint);
        
        // Create the identity bundle
        self.identity_keys = Some(IdentityKeyBundle {
            ed25519: IdentityEd25519 {
                public: ed25519_keypair.public.as_bytes().to_vec(),
                secret: ed25519_keypair.secret.as_bytes().to_vec(),
            },
            x25519: IdentityX25519 {
                public: x25519_public.as_bytes().to_vec(),
                secret: x25519_secret.to_bytes().to_vec(),
            },
            kyber: kyber_keypair,
            fingerprint,
            alias,
        });
        
        // Generate prekeys
        debug!("Generating prekeys");
        self.generate_prekeys(10)?;
        
        // Save identity to disk
        self.save_identity()?;
        
        info!("Identity keys generated successfully");
        Ok(self.identity_keys.as_ref().unwrap())
    }
    
    pub fn generate_prekeys(&mut self, count: usize) -> Result<(), KeyManagerError> {
        info!("Generating {} new prekeys", count);
        
        if self.identity_keys.is_none() {
            error!("Cannot generate prekeys: No identity keys available");
            return Err(KeyManagerError::KeyNotFound);
        }
        
        let mut new_prekeys = Vec::with_capacity(count);
        
        for i in 0..count {
            debug!("Generating prekey #{}", i);
            
            // Generate random key ID
            let mut key_id = [0u8; 16];
            rand::thread_rng().fill(&mut key_id);
            
            // Generate X25519 keypair for this prekey
            let csprng = OsRng07{};
            let x25519_secret = X25519SecretKey::new(csprng);
            let x25519_public = X25519PublicKey::from(&x25519_secret);
            
            // Generate Kyber keypair for this prekey
            let mut rng = rand::thread_rng();
            let kyber_keypair = KyberKeypair::generate(&mut rng);
            
            new_prekeys.push(PreKeyBundle {
                key_id: key_id.to_vec(),
                x25519: x25519_public.as_bytes().to_vec(),
                kyber: kyber_keypair.public,
            });
        }
        
        // Add new prekeys to existing list
        self.prekeys.extend(new_prekeys);
        
        // Save prekeys to disk
        self.save_prekeys()?;
        
        info!("Generated and saved {} prekeys", count);
        Ok(())
    }
    
    pub fn import_peer_key(&mut self, key_data: &[u8], alias: Option<String>) -> Result<String, KeyManagerError> {
        info!("Importing peer public key");
        
        // Deserialize the public key bundle
        let peer_key: IdentityKeyBundle = match serde_json::from_slice(key_data) {
            Ok(key) => {
                debug!("Successfully parsed peer key data");
                key
            },
            Err(e) => {
                error!("Failed to parse peer key data: {}", e);
                return Err(KeyManagerError::SerializationError(e));
            }
        };
        
        // Verify fingerprint matches the public keys
        let mut hasher = Sha256::new();
        hasher.update(&peer_key.ed25519.public);
        hasher.update(&peer_key.x25519.public);
        hasher.update(peer_key.kyber.public.as_bytes());
        let calculated_fingerprint = hex::encode(hasher.finalize());
        
        if calculated_fingerprint != peer_key.fingerprint {
            error!("Fingerprint mismatch in imported key: {} vs calculated {}", 
                  peer_key.fingerprint, calculated_fingerprint);
            return Err(KeyManagerError::InvalidKey);
        }
        
        debug!("Verified fingerprint for peer key: {}", peer_key.fingerprint);
        
        // Store the peer key with alias if provided
        let mut updated_peer_key = peer_key.clone();
        if let Some(name) = alias {
            debug!("Setting peer alias to: {}", name);
            updated_peer_key.alias = Some(name);
        }
        
        self.peer_keys.insert(updated_peer_key.fingerprint.clone(), updated_peer_key);
        
        // Save peer keys to disk
        self.save_peers()?;
        
        info!("Successfully imported peer key with fingerprint: {}", peer_key.fingerprint);
        Ok(peer_key.fingerprint)
    }
    
    pub fn export_public_key(&self) -> Result<Vec<u8>, KeyManagerError> {
        info!("Exporting public key");
        
        let identity = match &self.identity_keys {
            Some(keys) => keys,
            None => {
                error!("Cannot export public key: No identity keys available");
                return Err(KeyManagerError::KeyNotFound);
            }
        };
        
        // Create a public-only version of the identity bundle
        let public_bundle = IdentityKeyBundle {
            ed25519: IdentityEd25519 {
                public: identity.ed25519.public.clone(),
                secret: Vec::new(), // Empty secret key
            },
            x25519: IdentityX25519 {
                public: identity.x25519.public.clone(),
                secret: Vec::new(), // Empty secret key
            },
            kyber: KyberKeypair {
                public: identity.kyber.public.clone(),
                secret: KyberSecretKey { data: Vec::new() }, // Empty secret key
            },
            fingerprint: identity.fingerprint.clone(),
            alias: identity.alias.clone(),
        };
        
        // Serialize to JSON
        match serde_json::to_vec(&public_bundle) {
            Ok(data) => {
                debug!("Successfully serialized public key bundle, size: {} bytes", data.len());
                Ok(data)
            },
            Err(e) => {
                error!("Failed to serialize public key bundle: {}", e);
                Err(KeyManagerError::SerializationError(e))
            }
        }
    }
    
    pub fn create_session(&mut self, peer_fingerprint: &str) -> Result<&Session, KeyManagerError> {
        info!("Creating session with peer: {}", peer_fingerprint);
        
        // Check if we have identity keys
        let identity = match &self.identity_keys {
            Some(keys) => keys,
            None => {
                error!("Cannot create session: No identity keys available");
                return Err(KeyManagerError::KeyNotFound);
            }
        };
        
        // Check if we have the peer's keys
        let peer = match self.peer_keys.get(peer_fingerprint) {
            Some(keys) => {
                debug!("Found peer key: {}", peer_fingerprint);
                keys
            },
            None => {
                error!("Cannot create session: Peer not found: {}", peer_fingerprint);
                return Err(KeyManagerError::KeyNotFound);
            }
        };
        
        // Get our X25519 secret key
        let mut secret_bytes = [0u8; 32];
        if identity.x25519.secret.len() >= 32 {
            secret_bytes.copy_from_slice(&identity.x25519.secret[0..32]);
        } else {
            error!("Invalid X25519 secret key length");
            return Err(KeyManagerError::InvalidKey);
        }
        let my_secret = X25519SecretKey::from(secret_bytes);
        
        // Get peer's X25519 public key
        let mut public_bytes = [0u8; 32];
        let x25519_shared;
        if peer.x25519.public.len() >= 32 {
            public_bytes.copy_from_slice(&peer.x25519.public[0..32]);
            let peer_public = X25519PublicKey::from(public_bytes);
            x25519_shared = my_secret.diffie_hellman(&peer_public);
        } else {
            error!("Invalid peer X25519 public key length");
            return Err(KeyManagerError::InvalidKey);
        }
        
        // Generate Kyber shared secret
        let mut rng = rand::thread_rng();
        let (kyber_shared, _) = kyber::encapsulate(&mut rng, &peer.kyber.public);
        
        // Combine X25519 and Kyber shared secrets for hybrid post-quantum security
        let mut combined_shared = Vec::with_capacity(x25519_shared.as_bytes().len() + kyber_shared.len());
        combined_shared.extend_from_slice(x25519_shared.as_bytes());
        combined_shared.extend_from_slice(&kyber_shared);
        
        // Generate root key from combined shared secret
        let mut hasher = Sha256::new();
        hasher.update(&combined_shared);
        hasher.update(b"SecNetRoot");
        let root_key = hasher.finalize().to_vec();
        
        // Generate chain key from root key
        let mut hasher = Sha256::new();
        hasher.update(&root_key);
        hasher.update(b"SecNetChain");
        let chain_key = hasher.finalize().to_vec();
        
        // Generate sending ratchet key
        let csprng = OsRng07{};
        let ratchet_secret = X25519SecretKey::new(csprng);
        let _ratchet_public = X25519PublicKey::from(&ratchet_secret);
        
        // Initialize ratchet state for Double Ratchet Algorithm
        let ratchet_state = RatchetState {
            dh_s: ratchet_secret.to_bytes().to_vec(),
            dh_r: Some(peer.x25519.public.clone()),
            root_key: root_key.clone(),
            send_chain_key: chain_key.clone(),
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            ratchet_flag: false,
        };
        
        // Create session
        let session = Session {
            remote_fingerprint: peer_fingerprint.to_string(),
            shared_secret: combined_shared,
            root_key,
            chain_key,
            message_counter: 0,
            prekey_id: None,
            ratchet_state,
        };
        
        // Store session
        self.sessions.insert(peer_fingerprint.to_string(), session.clone());
        
        // Save sessions to disk
        self.save_sessions()?;
        
        info!("Session created successfully with peer: {}", peer_fingerprint);
        Ok(self.sessions.get(peer_fingerprint).unwrap())
    }
    
    // Private helper methods for saving data
    
    fn save_identity(&self) -> Result<(), KeyManagerError> {
        debug!("Saving identity to disk");
        
        if let Some(identity) = &self.identity_keys {
            let path = format!("{}/identity.json", self.storage_path);
            debug!("Writing identity to path: {}", path);
            
            let mut file = File::create(&path)?;
            let json = serde_json::to_string_pretty(identity)?;
            file.write_all(json.as_bytes())?;
            
            info!("Identity saved successfully to: {}", path);
            Ok(())
        } else {
            warn!("No identity to save");
            Ok(())
        }
    }
    
    fn save_peers(&self) -> Result<(), KeyManagerError> {
        debug!("Saving {} peers to disk", self.peer_keys.len());
        
        let path = format!("{}/peers.json", self.storage_path);
        let mut file = File::create(&path)?;
        let json = serde_json::to_string_pretty(&self.peer_keys)?;
        file.write_all(json.as_bytes())?;
        
        info!("Peers saved successfully to: {}", path);
        Ok(())
    }
    
    fn save_sessions(&self) -> Result<(), KeyManagerError> {
        debug!("Saving {} sessions to disk", self.sessions.len());
        
        let path = format!("{}/sessions.json", self.storage_path);
        let mut file = File::create(&path)?;
        let json = serde_json::to_string_pretty(&self.sessions)?;
        file.write_all(json.as_bytes())?;
        
        info!("Sessions saved successfully to: {}", path);
        Ok(())
    }
    
    fn save_prekeys(&self) -> Result<(), KeyManagerError> {
        debug!("Saving {} prekeys to disk", self.prekeys.len());
        
        let path = format!("{}/prekeys.json", self.storage_path);
        let mut file = File::create(&path)?;
        let json = serde_json::to_string_pretty(&self.prekeys)?;
        file.write_all(json.as_bytes())?;
        
        info!("Prekeys saved successfully to: {}", path);
        Ok(())
    }
    
    // Public methods for accessing stored data
    
    pub fn get_identity(&self) -> Option<&IdentityKeyBundle> {
        self.identity_keys.as_ref()
    }
    
    pub fn get_peer(&self, fingerprint: &str) -> Option<&IdentityKeyBundle> {
        self.peer_keys.get(fingerprint)
    }
    
    pub fn get_peers(&self) -> &HashMap<String, IdentityKeyBundle> {
        &self.peer_keys
    }
    
    pub fn get_session(&self, fingerprint: &str) -> Option<&Session> {
        self.sessions.get(fingerprint)
    }
    
    pub fn get_session_mut(&mut self, fingerprint: &str) -> Option<&mut Session> {
        self.sessions.get_mut(fingerprint)
    }
    
    pub fn get_prekeys(&self) -> &[PreKeyBundle] {
        &self.prekeys
    }
    
    pub fn remove_peer(&mut self, fingerprint: &str) -> Result<(), KeyManagerError> {
        info!("Removing peer: {}", fingerprint);
        
        if self.peer_keys.remove(fingerprint).is_some() {
            debug!("Peer removed from memory: {}", fingerprint);
            
            // Also remove any session with this peer
            self.sessions.remove(fingerprint);
            debug!("Removed associated session for peer: {}", fingerprint);
            
            // Save changes to disk
            self.save_peers()?;
            self.save_sessions()?;
            
            info!("Peer and associated session removed successfully: {}", fingerprint);
            Ok(())
        } else {
            warn!("Peer not found for removal: {}", fingerprint);
            Err(KeyManagerError::KeyNotFound)
        }
    }
    
    // Double Ratchet Based Encryption/Decryption
    
    pub fn encrypt_message(&mut self, peer_fingerprint: &str, message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        info!("Encrypting message for peer: {}", peer_fingerprint);
        trace!("Message length: {} bytes", message.len());
        
        // Get or create session
        if self.get_session(peer_fingerprint).is_none() {
            debug!("No existing session, creating new one for peer: {}", peer_fingerprint);
            self.create_session(peer_fingerprint)?;
        } else {
            debug!("Using existing session for peer: {}", peer_fingerprint);
        }
        
        // Check if ratchet is needed
        let need_ratchet = {
            let session = self.get_session(peer_fingerprint).unwrap();
            session.ratchet_state.ratchet_flag
        };
        
        // Perform ratchet if needed
        if need_ratchet {
            self.ratchet_dh(peer_fingerprint)?;
        }
        
        // Get current state
        let (chain_key, counter, prev_counter) = {
            let session = self.get_session(peer_fingerprint).unwrap();
            (
                session.ratchet_state.send_chain_key.clone(),
                session.ratchet_state.send_count,
                session.ratchet_state.prev_send_count
            )
        };
        
        // Derive message key
        let message_key = self.derive_message_key(&chain_key, counter)?;
        
        // Increment counter and construct header
        {
            let session = self.get_session_mut(peer_fingerprint).unwrap();
            session.ratchet_state.send_count += 1;
        }
        
        // Get public ratchet key
        let public_key = self.get_public_ratchet_key(peer_fingerprint)?;
        
        // Create header
        let header = MessageHeader {
            dh: public_key,
            pn: prev_counter,
            n: counter,
        };
        
        // Encrypt message with message key using ChaCha20-Poly1305
        let nonce_bytes = counter.to_be_bytes();
        let mut nonce = [0u8; 12]; // ChaCha20-Poly1305 needs a 12-byte nonce
        nonce[8..12].copy_from_slice(&nonce_bytes);
        
        let encryption_key = Key::from_slice(&message_key);
        let cipher = ChaCha20Poly1305::new(encryption_key);
        let nonce = Nonce::from_slice(&nonce);
        
        let serialized_header = serde_json::to_vec(&header)
            .map_err(|e| KeyManagerError::EncryptionError(format!("Failed to serialize header: {}", e)))?;
        
        // Encrypt message
        let ciphertext = cipher.encrypt(nonce, message)
            .map_err(|_| KeyManagerError::EncryptionError("Encryption failed".to_string()))?;
        
        // Create encrypted message with header
        let mut encrypted_message = Vec::with_capacity(serialized_header.len() + ciphertext.len() + 4);
        encrypted_message.extend_from_slice(&(serialized_header.len() as u32).to_be_bytes());
        encrypted_message.extend_from_slice(&serialized_header);
        encrypted_message.extend_from_slice(&ciphertext);
        
        // Save updated session
        self.save_sessions()?;
        
        trace!("Encrypted message length: {} bytes", encrypted_message.len());
        info!("Message encrypted successfully for peer: {}", peer_fingerprint);
        Ok(encrypted_message)
    }
    
    pub fn decrypt_message(&mut self, peer_fingerprint: &str, encrypted_message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        info!("Decrypting message from peer: {}", peer_fingerprint);
        trace!("Encrypted message length: {} bytes", encrypted_message.len());
        
        // Get session
        if self.get_session(peer_fingerprint).is_none() {
            error!("No session found for peer: {}", peer_fingerprint);
            return Err(KeyManagerError::KeyNotFound);
        }
        
        // Parse encrypted message format
        if encrypted_message.len() < 4 {
            return Err(KeyManagerError::DecryptionError("Message too short".to_string()));
        }
        
        let header_len = u32::from_be_bytes([
            encrypted_message[0], encrypted_message[1], 
            encrypted_message[2], encrypted_message[3]
        ]) as usize;
        
        if encrypted_message.len() < 4 + header_len {
            return Err(KeyManagerError::DecryptionError("Invalid message format".to_string()));
        }
        
        let header_bytes = &encrypted_message[4..4 + header_len];
        let ciphertext = &encrypted_message[4 + header_len..];
        
        // Deserialize header
        let header: MessageHeader = serde_json::from_slice(header_bytes)
            .map_err(|e| KeyManagerError::DecryptionError(format!("Failed to deserialize header: {}", e)))?;
        
        // Check if we need to perform a DH ratchet step
        let (dh_ratchet_needed, _current_remote_key) = {
            let session = self.get_session(peer_fingerprint).unwrap();
            match &session.ratchet_state.dh_r {
                Some(current_remote_key) => {
                    // Compare current remote key with the one in the message
                    (&header.dh != current_remote_key.as_slice(), current_remote_key.clone())
                },
                None => (true, Vec::new()) // No remote key, so we need to ratchet
            }
        };
        
        // Save remote key from header and perform ratchet if needed
        if dh_ratchet_needed {
            debug!("DH ratchet step needed");
            // Save current remote key from header
            {
                let session = self.get_session_mut(peer_fingerprint).unwrap();
                session.ratchet_state.dh_r = Some(header.dh.clone());
            }
            
            // Perform DH ratchet step
            self.ratchet_dh(peer_fingerprint)?;
        }
        
        // Update receive counter if needed
        {
            let session = self.get_session_mut(peer_fingerprint).unwrap();
            if header.n > session.ratchet_state.recv_count {
                session.ratchet_state.recv_count = header.n;
            }
        }
        
        // Get current chain key
        let recv_chain_key = {
            let session = self.get_session(peer_fingerprint).unwrap();
            session.ratchet_state.recv_chain_key.clone().unwrap_or_default()
        };
        
        // Derive message key
        let message_key = self.derive_message_key(&recv_chain_key, header.n)?;
        
        // Decrypt message
        let nonce_bytes = header.n.to_be_bytes();
        let mut nonce = [0u8; 12];
        nonce[8..12].copy_from_slice(&nonce_bytes);
        
        let decryption_key = Key::from_slice(&message_key);
        let cipher = ChaCha20Poly1305::new(decryption_key);
        let nonce = Nonce::from_slice(&nonce);
        
        let decrypted = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| KeyManagerError::DecryptionError("Decryption failed".to_string()))?;
        
        // Save updated session
        self.save_sessions()?;
        
        trace!("Decrypted message length: {} bytes", decrypted.len());
        info!("Message decrypted successfully from peer: {}", peer_fingerprint);
        Ok(decrypted)
    }
    
    // Helper methods for Double Ratchet Algorithm
    
    fn derive_message_key(&self, chain_key: &[u8], counter: u32) -> Result<Vec<u8>, KeyManagerError> {
        let mut key = chain_key.to_vec();
        
        // Derive keys in chain until we reach the desired counter
        for _i in 0..counter {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            hasher.update(&[0x01]); // Message key derivation constant
            key = hasher.finalize().to_vec();
        }
        
        // Final message key
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hasher.update(&[0x02]); // Message key derivation constant
        Ok(hasher.finalize().to_vec())
    }
    
    pub fn ratchet_dh(&mut self, peer_fingerprint: &str) -> Result<(), KeyManagerError> {
        debug!("Performing DH ratchet step for peer: {}", peer_fingerprint);
        
        // Clone the necessary data from the session to avoid double borrowing
        let session_data = {
            let session = self.get_session_mut(peer_fingerprint)
                .ok_or_else(|| KeyManagerError::KeyNotFound)?;
                
            // Clone the data we need
            (
                session.ratchet_state.dh_s.clone(),
                session.ratchet_state.dh_r.clone(),
                session.ratchet_state.root_key.clone()
            )
        };
        
        let (dh_s, dh_r_opt, root_key) = session_data;
        
        // Get remote ratchet key
        let remote_key = match dh_r_opt {
            Some(key) => key,
            None => {
                error!("No remote ratchet key available");
                return Err(KeyManagerError::KeyNotFound);
            }
        };
        
        // Convert to X25519 keys
        let dh_secret = match <[u8; 32]>::try_from(&dh_s[..]) {
            Ok(array) => X25519SecretKey::from(array),
            Err(_) => {
                error!("Invalid local ratchet secret key");
                return Err(KeyManagerError::InvalidKey);
            }
        };
        
        let dh_remote = match <[u8; 32]>::try_from(&remote_key[..]) {
            Ok(array) => X25519PublicKey::from(array),
            Err(_) => {
                error!("Invalid remote ratchet public key");
                return Err(KeyManagerError::InvalidKey);
            }
        };
        
        // Generate DH output
        let dh_out = dh_secret.diffie_hellman(&dh_remote);
        
        // Generate new ratchet key pair
        let csprng = OsRng07{};
        let new_dh_secret = X25519SecretKey::new(csprng);
        let _new_dh_public = X25519PublicKey::from(&new_dh_secret);

        
        // Now update the session with new keys
        {
            let session = self.get_session_mut(peer_fingerprint)
                .ok_or_else(|| KeyManagerError::KeyNotFound)?;
            
            // Store previous send count
            session.ratchet_state.prev_send_count = session.ratchet_state.send_count;
            session.ratchet_state.send_count = 0;
            
            // Update root key, chain keys and ratchet keys
            let mut kdf_input = Vec::with_capacity(root_key.len() + dh_out.as_bytes().len());
            kdf_input.extend_from_slice(&root_key);
            kdf_input.extend_from_slice(dh_out.as_bytes());
            
            let mut hasher = Sha256::new();
            hasher.update(&kdf_input);
            hasher.update(b"RootKeyUpdate");
            let new_root_key = hasher.finalize().to_vec();
            
            // Generate new chain keys
            let mut hasher = Sha256::new();
            hasher.update(&new_root_key);
            hasher.update(b"ChainKeySend");
            let new_send_chain = hasher.finalize().to_vec();
            
            let mut hasher = Sha256::new();
            hasher.update(&new_root_key);
            hasher.update(b"ChainKeyRecv");
            let new_recv_chain = hasher.finalize().to_vec();
            
            // Update session state
            session.ratchet_state.root_key = new_root_key;
            session.ratchet_state.send_chain_key = new_send_chain;
            session.ratchet_state.recv_chain_key = Some(new_recv_chain);
            session.ratchet_state.dh_s = new_dh_secret.to_bytes().to_vec();
            session.ratchet_state.ratchet_flag = false; // Reset ratchet flag
        }
        
        debug!("DH ratchet step completed successfully");
        Ok(())
    }
    
    fn get_public_ratchet_key(&self, peer_fingerprint: &str) -> Result<Vec<u8>, KeyManagerError> {
        let session = match self.get_session(peer_fingerprint) {
            Some(s) => s,
            None => {
                error!("No session found for peer: {}", peer_fingerprint);
                return Err(KeyManagerError::KeyNotFound);
            }
        };
        
        // Convert private key to public key
        let dh_secret = match <[u8; 32]>::try_from(&session.ratchet_state.dh_s[..]) {
            Ok(array) => X25519SecretKey::from(array),
            Err(_) => {
                error!("Invalid ratchet secret key length");
                return Err(KeyManagerError::InvalidKey);
            }
        };
        
        let dh_public = X25519PublicKey::from(&dh_secret);
        Ok(dh_public.as_bytes().to_vec())
    }
    
    pub fn backup_keys(&self, backup_path: &str, password: &str) -> Result<(), KeyManagerError> {
        info!("Creating encrypted backup of all keys to: {}", backup_path);
        
        if self.identity_keys.is_none() {
            error!("Cannot create backup: No identity keys available");
            return Err(KeyManagerError::KeyNotFound);
        }
        
        // Create a backup structure with all keys
        let backup = KeyBackup {
            identity: self.identity_keys.clone().unwrap(),
            peers: self.peer_keys.clone(),
            sessions: self.sessions.clone(),
            prekeys: self.prekeys.clone(),
        };
        
        // Serialize to JSON
        let json = serde_json::to_string(&backup)?;
        
        // Properly encrypt data with password using authenticated encryption
        
        // Derive key from password using PBKDF2 (simplified here, use argon2 in real implementation)
        let salt = rand::thread_rng().gen::<[u8; 16]>();
        let mut key = [0u8; 32];
        
        // Derive key from password (very insecure, just for simulation)
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&salt);
        key.copy_from_slice(&hasher.finalize());
        
        // Encrypt JSON using ChaCha20-Poly1305
        let encryption_key = Key::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(encryption_key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the data
        let ciphertext = cipher.encrypt(nonce, json.as_bytes())
            .map_err(|_| KeyManagerError::EncryptionError("Backup encryption failed".to_string()))?;
        
        // Write salt, nonce, and encrypted data to file
        let mut file = File::create(backup_path)?;
        file.write_all(&salt)?;
        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        
        info!("Backup created successfully at: {}", backup_path);
        Ok(())
    }
    
    pub fn restore_from_backup(&mut self, backup_path: &str, password: &str) -> Result<(), KeyManagerError> {
        info!("Restoring keys from backup: {}", backup_path);
        
        // Read backup file
        let mut file = File::open(backup_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        if data.len() < 28 { // 16 (salt) + 12 (nonce)
            error!("Backup file is too small to be valid");
            return Err(KeyManagerError::InvalidKey);
        }
        
        // Extract salt, nonce, and encrypted data
        let salt = &data[0..16];
        let nonce_bytes = &data[16..28];
        let encrypted = &data[28..];
        
        // Derive key from password
        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        key.copy_from_slice(&hasher.finalize());
        
        // Decrypt the data
        let decryption_key = Key::from_slice(&key);
        let cipher = ChaCha20Poly1305::new(decryption_key);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let decrypted = cipher.decrypt(nonce, encrypted)
            .map_err(|_| KeyManagerError::DecryptionError("Backup decryption failed - incorrect password?".to_string()))?;
        
        // Parse JSON
        let backup: KeyBackup = serde_json::from_slice(&decrypted)?;
        
        // Restore keys
        self.identity_keys = Some(backup.identity);
        self.peer_keys = backup.peers;
        self.sessions = backup.sessions;
        self.prekeys = backup.prekeys;
        
        // Save all restored data
        self.save_identity()?;
        self.save_peers()?;
        self.save_sessions()?;
        self.save_prekeys()?;
        
        info!("Keys restored successfully from backup");
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct KeyBackup {
    identity: IdentityKeyBundle,
    peers: HashMap<String, IdentityKeyBundle>,
    sessions: HashMap<String, Session>,
    prekeys: Vec<PreKeyBundle>,
}

// Message header for Double Ratchet
#[derive(Clone, Debug, Serialize, Deserialize)]
struct MessageHeader {
    pub dh: Vec<u8>,  // Sender's current ratchet public key
    pub pn: u32,      // Previous chain length
    pub n: u32,       // Message number in chain
}