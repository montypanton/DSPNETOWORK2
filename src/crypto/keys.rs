// client/src/crypto/keys.rs
use ed25519_dalek::{Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use rand_07::rngs::OsRng as OsRng07; // Using rand 0.7 explicitly for ed25519-dalek compatibility
use rand::{Rng, RngCore}; // Using rand 0.8 for general RNG
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

// We'll simulate Kyber with placeholder structs until we include the actual crate
// In a real implementation, we would use pqcrypto-kyber
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberPublicKey(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberSecretKey(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberKeypair {
    pub public: KyberPublicKey,
    pub secret: KyberSecretKey,
}

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
}

#[derive(Debug)]
pub enum KeyManagerError {
    IoError(std::io::Error),
    SerializationError(serde_json::Error),
    KeyGenerationError(String),
    KeyNotFound,
    InvalidKey,
}

impl fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyManagerError::IoError(e) => write!(f, "I/O error: {}", e),
            KeyManagerError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            KeyManagerError::KeyGenerationError(s) => write!(f, "Key generation error: {}", s),
            KeyManagerError::KeyNotFound => write!(f, "Key not found"),
            KeyManagerError::InvalidKey => write!(f, "Invalid key"),
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
        
        // Simulate generating Kyber keypair (in real implementation we'd use pqcrypto-kyber)
        debug!("Generating Kyber keypair (simulated)");
        let mut rng = rand::thread_rng();
        let kyber_secret_data: [u8; 32] = rng.gen();
        let kyber_public_data: [u8; 32] = rng.gen();
        
        let kyber_keypair = KyberKeypair {
            public: KyberPublicKey(kyber_public_data.to_vec()),
            secret: KyberSecretKey(kyber_secret_data.to_vec()),
        };
        
        // Calculate fingerprint (hash of all public keys)
        let mut hasher = Sha256::new();
        hasher.update(ed25519_keypair.public.as_bytes());
        hasher.update(x25519_public.as_bytes());
        hasher.update(&kyber_public_data);
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
            let mut csprng = OsRng07{};
            let x25519_secret = X25519SecretKey::new(csprng);
            let x25519_public = X25519PublicKey::from(&x25519_secret);
            
            // Simulate Kyber keypair for this prekey
            let mut rng = rand::thread_rng();
            let kyber_public_data: [u8; 32] = rng.gen();
            
            new_prekeys.push(PreKeyBundle {
                key_id: key_id.to_vec(),
                x25519: x25519_public.as_bytes().to_vec(),
                kyber: KyberPublicKey(kyber_public_data.to_vec()),
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
        hasher.update(&peer_key.kyber.public.0);
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
                public: KyberPublicKey(identity.kyber.public.0.clone()),
                secret: KyberSecretKey(Vec::new()), // Empty secret key
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
        
        // In a real implementation, we would use X25519 to generate a shared secret
        // and then combine it with a shared secret from Kyber for hybrid post-quantum security
        // For this simulation we'll just create a random shared secret
        
        // Generate random shared secret for simulation
        let mut shared_secret = [0u8; 32];
        rand::thread_rng().fill(&mut shared_secret);
        
        // Generate root key and chain key
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret);
        let root_key = hasher.finalize().to_vec();
        
        let mut hasher = Sha256::new();
        hasher.update(&root_key);
        let chain_key = hasher.finalize().to_vec();
        
        // Create session
        let session = Session {
            remote_fingerprint: peer_fingerprint.to_string(),
            shared_secret: shared_secret.to_vec(),
            root_key,
            chain_key,
            message_counter: 0,
            prekey_id: None,
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
    
    pub fn encrypt_message(&mut self, peer_fingerprint: &str, message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        info!("Encrypting message for peer: {}", peer_fingerprint);
        trace!("Message length: {} bytes", message.len());
        
        // Get or create session
        let _session = match self.get_session(peer_fingerprint) {
            Some(session) => {
                debug!("Using existing session for peer: {}", peer_fingerprint);
                session.clone()
            },
            None => {
                debug!("No existing session, creating new one for peer: {}", peer_fingerprint);
                self.create_session(peer_fingerprint)?.clone()
            }
        };
        
        // In a real implementation, we would:
        // 1. Update the ratchet if needed
        // 2. Derive a message key
        // 3. Encrypt the message with ChaCha20-Poly1305
        // 4. Sign the encrypted message
        // 5. Attach header information
        
        // For this simulation, we'll just do a simple encryption
        // Get mutable session to update the counter
        let session = self.get_session_mut(peer_fingerprint).unwrap();
        let counter = session.message_counter;
        session.message_counter += 1;
        
        // Derive message key from chain key and counter
        let mut hasher = Sha256::new();
        hasher.update(&session.chain_key);
        hasher.update(&counter.to_be_bytes());
        let message_key = hasher.finalize();
        
        // Simple XOR "encryption" for simulation
        // In a real implementation we would use ChaCha20-Poly1305
        let mut encrypted = Vec::with_capacity(message.len());
        for (i, byte) in message.iter().enumerate() {
            encrypted.push(byte ^ message_key[i % 32]);
        }
        
        // Save updated session
        self.save_sessions()?;
        
        trace!("Encrypted message length: {} bytes", encrypted.len());
        info!("Message encrypted successfully for peer: {}", peer_fingerprint);
        Ok(encrypted)
    }
    
    pub fn decrypt_message(&mut self, peer_fingerprint: &str, encrypted_message: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        info!("Decrypting message from peer: {}", peer_fingerprint);
        trace!("Encrypted message length: {} bytes", encrypted_message.len());
        
        // Get session
        let _session = match self.get_session(peer_fingerprint) {
            Some(session) => {
                debug!("Using existing session for peer: {}", peer_fingerprint);
                session.clone()
            },
            None => {
                error!("No session found for peer: {}", peer_fingerprint);
                return Err(KeyManagerError::KeyNotFound);
            }
        };
        
        // In a real implementation, we would:
        // 1. Verify the message signature
        // 2. Update the ratchet if needed
        // 3. Derive the message key
        // 4. Decrypt the message with ChaCha20-Poly1305
        
        // For this simulation, we'll just do a simple decryption
        // Get mutable session to update the counter
        let session = self.get_session_mut(peer_fingerprint).unwrap();
        let counter = session.message_counter;
        session.message_counter += 1;
        
        // Derive message key from chain key and counter
        let mut hasher = Sha256::new();
        hasher.update(&session.chain_key);
        hasher.update(&counter.to_be_bytes());
        let message_key = hasher.finalize();
        
        // Simple XOR "decryption" for simulation
        // In a real implementation we would use ChaCha20-Poly1305
        let mut decrypted = Vec::with_capacity(encrypted_message.len());
        for (i, byte) in encrypted_message.iter().enumerate() {
            decrypted.push(byte ^ message_key[i % 32]);
        }
        
        // Save updated session
        self.save_sessions()?;
        
        trace!("Decrypted message length: {} bytes", decrypted.len());
        info!("Message decrypted successfully from peer: {}", peer_fingerprint);
        Ok(decrypted)
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
        
        // In a real implementation, we would properly encrypt this with the password
        // For simulation, we'll just do a very basic "encryption"
        let salt = [42u8; 16]; // Fixed salt for simulation
        let mut key = [0u8; 32];
        
        // Derive key from password (very insecure, just for simulation)
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(&salt);
        key.copy_from_slice(&hasher.finalize());
        
        // "Encrypt" JSON (just XOR with key)
        let mut encrypted = Vec::with_capacity(json.len());
        for (i, byte) in json.as_bytes().iter().enumerate() {
            encrypted.push(byte ^ key[i % 32]);
        }
        
        // Write to file
        let mut file = File::create(backup_path)?;
        file.write_all(&salt)?; // Write salt
        file.write_all(&encrypted)?; // Write "encrypted" data
        
        info!("Backup created successfully at: {}", backup_path);
        Ok(())
    }
    
    pub fn restore_from_backup(&mut self, backup_path: &str, password: &str) -> Result<(), KeyManagerError> {
        info!("Restoring keys from backup: {}", backup_path);
        
        // Read backup file
        let mut file = File::open(backup_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        if data.len() < 16 {
            error!("Backup file is too small to be valid");
            return Err(KeyManagerError::InvalidKey);
        }
        
        // Extract salt and encrypted data
        let salt = &data[0..16];
        let encrypted = &data[16..];
        
        // Derive key from password (very insecure, just for simulation)
        let mut key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        key.copy_from_slice(&hasher.finalize());
        
        // "Decrypt" data (just XOR with key)
        let mut decrypted = Vec::with_capacity(encrypted.len());
        for (i, byte) in encrypted.iter().enumerate() {
            decrypted.push(byte ^ key[i % 32]);
        }
        
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