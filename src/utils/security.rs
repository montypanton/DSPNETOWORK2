// src/utils/security.rs
// Enhanced security utilities for SecNet

use log::{debug, error, info, warn};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};
use sha3::{Sha3_256, Sha3_512};
use std::time::{SystemTime, UNIX_EPOCH};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

/// Generate a cryptographically secure random ID
pub fn generate_secure_id(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    thread_rng().fill(&mut bytes[..]);
    bytes
}

/// Generate a secure authentication token
pub fn generate_auth_token() -> String {
    let mut token_bytes = [0u8; 32];
    thread_rng().fill(&mut token_bytes);
    hex::encode(token_bytes)
}

/// Create a blinded token using SHA3 (resistant to length extension attacks)
pub fn blind_token(token: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(token);
    hasher.update(context);
    hasher.update(b"SecNetBlinding");
    hasher.finalize().to_vec()
}

/// Constant time comparison to prevent timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

/// Create a secure HMAC using SHA256
pub fn create_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac_key = [0u8; 32];
    
    // If key is longer than 32 bytes, hash it first
    if key.len() > 32 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hmac_key.copy_from_slice(&hasher.finalize());
    } else {
        // Otherwise use the key directly with padding
        hmac_key[..key.len()].copy_from_slice(key);
    }
    
    // Inner hash
    let inner_pad = hmac_key.iter().map(|b| b ^ 0x36).collect::<Vec<_>>();
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&inner_pad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();
    
    // Outer hash
    let outer_pad = hmac_key.iter().map(|b| b ^ 0x5c).collect::<Vec<_>>();
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&outer_pad);
    outer_hasher.update(&inner_hash);
    
    outer_hasher.finalize().to_vec()
}

/// Check system entropy 
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

/// Encrypt data with key
pub fn encrypt_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Encryption key must be 32 bytes".to_string());
    }
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12]; // ChaCha20-Poly1305 needs a 12-byte nonce
    thread_rng().fill(&mut nonce_bytes);
    
    // Encrypt data
    let encryption_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(encryption_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    match cipher.encrypt(nonce, data) {
        Ok(ciphertext) => {
            // Return nonce + ciphertext
            let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            Ok(result)
        },
        Err(_) => Err("Encryption failed".to_string()),
    }
}

/// Decrypt data with key
pub fn decrypt_data(key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Decryption key must be 32 bytes".to_string());
    }
    
    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }
    
    // Extract nonce and ciphertext
    let nonce_bytes = &encrypted_data[0..12];
    let ciphertext = &encrypted_data[12..];
    
    // Decrypt data
    let decryption_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(decryption_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err("Decryption failed".to_string()),
    }
}

/// Generate a secure device ID
pub fn generate_device_id() -> String {
    let mut id_bytes = [0u8; 16];
    thread_rng().fill(&mut id_bytes);
    hex::encode(id_bytes)
}

/// Derive a key from password using SHA3 (simple KDF)
pub fn derive_key_from_password(password: &str, salt: &[u8], iterations: usize) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(password.as_bytes());
    key.extend_from_slice(salt);
    
    // Apply multiple iterations of SHA3
    for _ in 0..iterations {
        let mut hasher = Sha3_512::new();
        hasher.update(&key);
        key = hasher.finalize().to_vec();
    }
    
    // Return only first 32 bytes for ChaCha20-Poly1305
    key[0..32].to_vec()
}

/// Generate a secure session ID
pub fn generate_session_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let mut random_bytes = [0u8; 16];
    thread_rng().fill(&mut random_bytes);
    
    let mut hasher = Sha256::new();
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(&random_bytes);
    hex::encode(&hasher.finalize()[0..16]) // 16 bytes is enough for session ID
}

/// Obfuscate metadata to enhance privacy
pub fn obfuscate_metadata(data: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.update(context);
    hasher.update(b"SecNetMetadata");
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_constant_time_eq() {
        let a = b"same data";
        let b = b"same data";
        let c = b"different";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
    }
    
    #[test]
    fn test_hmac() {
        let key = b"test key";
        let data = b"test data";
        
        let hmac1 = create_hmac(key, data);
        let hmac2 = create_hmac(key, data);
        let hmac3 = create_hmac(key, b"different data");
        
        assert!(constant_time_eq(&hmac1, &hmac2));
        assert!(!constant_time_eq(&hmac1, &hmac3));
    }
    
    #[test]
    fn test_encryption_decryption() {
        let key = generate_secure_id(32);
        let data = b"This is a test message for encryption";
        
        let encrypted = encrypt_data(&key, data).unwrap();
        let decrypted = decrypt_data(&key, &encrypted).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
    
    #[test]
    fn test_key_derivation() {
        let password = "test password";
        let salt = b"test salt";
        
        let key1 = derive_key_from_password(password, salt, 1000);
        let key2 = derive_key_from_password(password, salt, 1000);
        let key3 = derive_key_from_password("different password", salt, 1000);
        
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_eq!(key1.len(), 32); // Key should be 32 bytes for ChaCha20-Poly1305
    }
}