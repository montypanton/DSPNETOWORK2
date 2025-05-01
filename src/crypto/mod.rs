// src/crypto/mod.rs
// This module brings together all the cryptographic components

pub mod keys;
pub mod kyber;
pub mod ratchet;

// Re-export commonly used types
pub use keys::{
    KeyManager, KeyManagerError,
    IdentityKeyBundle, Session, RatchetState,
    IdentityEd25519, IdentityX25519, PreKeyBundle
};

pub use kyber::{
    KyberKeypair, KyberPublicKey, KyberSecretKey, KyberCiphertext,
    encapsulate, decapsulate
};

// Utility function to verify a fingerprint
pub fn verify_fingerprint(fingerprint: &str, ed25519_key: &[u8], x25519_key: &[u8], kyber_key: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    
    let mut hasher = Sha256::new();
    hasher.update(ed25519_key);
    hasher.update(x25519_key);
    hasher.update(kyber_key);
    let calculated = hex::encode(hasher.finalize());
    
    // Compare in constant time to prevent timing attacks
    if fingerprint.len() != calculated.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (a, b) in fingerprint.bytes().zip(calculated.bytes()) {
        result |= a ^ b;
    }
    
    result == 0
}

// Generate a random authentication token
pub fn generate_auth_token() -> String {
    use rand::{RngCore, thread_rng};
    use base64::{Engine as _, engine::general_purpose};
    
    let mut token_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut token_bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
}

// Cryptographic version information
pub const CRYPTO_VERSION: &str = "1.0.0";
pub const SUPPORTED_ALGORITHMS: &[&str] = &[
    "Ed25519", "X25519", "Kyber-768", "ChaCha20-Poly1305", "SHA-256", "HMAC-SHA256"
];

// Check if the system has sufficient entropy for secure key generation
pub fn check_system_entropy() -> (bool, Option<u32>) {
    #[cfg(target_family = "unix")]
    {
        // Try to read entropy estimate on Linux
        if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/random/entropy_avail") {
            if let Ok(entropy) = content.trim().parse::<u32>() {
                return (entropy >= 256, Some(entropy));
            }
        }
    }
    
    // For other platforms or if reading failed, we can't determine exact entropy
    // but we assume it's sufficient on modern systems
    (true, None)
}