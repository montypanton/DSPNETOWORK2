// src/utils/metadata.rs
// Metadata protection for enhanced privacy

use log::{debug, info, warn};
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha3_256, Sha3_512};
use std::time::{SystemTime, UNIX_EPOCH};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};

/// Generate a random message ID that doesn't leak information
pub fn generate_message_id() -> Vec<u8> {
    let mut id_bytes = [0u8; 32];
    thread_rng().fill(&mut id_bytes);
    id_bytes.to_vec()
}

/// Create a blinded token for topics to prevent user tracking
pub fn blind_token(token: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(token);
    hasher.update(context);
    hasher.update(b"SecNetBlinding");
    hasher.finalize().to_vec()
}

/// Encrypt message metadata
pub fn encrypt_metadata(
    sender_fingerprint: &str,
    recipient_fingerprint: &str,
    timestamp: u64,
    key: &[u8]
) -> Result<Vec<u8>, String> {
    // Create metadata structure
    let metadata = format!("{{\"s\":\"{}\",\"r\":\"{}\",\"t\":{}}}", 
                          sender_fingerprint, recipient_fingerprint, timestamp);
    
    // Encrypt metadata
    encrypt_data(key, metadata.as_bytes())
}

/// Decrypt message metadata
pub fn decrypt_metadata(
    encrypted_metadata: &[u8],
    key: &[u8]
) -> Result<(String, String, u64), String> {
    // Decrypt the metadata
    let decrypted = decrypt_data(key, encrypted_metadata)?;
    
    // Parse JSON (simplified)
    let json = String::from_utf8(decrypted)
        .map_err(|_| "Invalid metadata format".to_string())?;
    
    // Very simple JSON parsing for demonstration
    // In a real implementation, use serde_json
    
    let sender = json
        .split("\"s\":\"").nth(1)
        .and_then(|s| s.split("\"").next())
        .ok_or_else(|| "Invalid metadata format".to_string())?;
    
    let recipient = json
        .split("\"r\":\"").nth(1)
        .and_then(|s| s.split("\"").next())
        .ok_or_else(|| "Invalid metadata format".to_string())?;
    
    let timestamp = json
        .split("\"t\":").nth(1)
        .and_then(|s| s.split("}").next())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| "Invalid metadata format".to_string())?;
    
    Ok((sender.to_string(), recipient.to_string(), timestamp))
}

/// Create privacy-preserving message routing information
pub fn create_routing_info(
    recipient_key_hash: &[u8],
    sender_key_hash: &[u8],
    topic_id: Option<&[u8]>
) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(recipient_key_hash);
    hasher.update(sender_key_hash);
    
    if let Some(topic) = topic_id {
        hasher.update(topic);
    }
    
    hasher.update(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_be_bytes());
    
    hasher.finalize().to_vec()
}

/// Create a secure padded envelope for messages
/// This helps hide the actual message size from network observers
pub fn create_padded_envelope(message: &[u8], block_size: usize) -> Vec<u8> {
    // Determine padding amount 
    // We pad to the next multiple of block_size plus a random amount
    let base_size = (message.len() / block_size + 1) * block_size;
    let random_padding = thread_rng().gen_range(0..block_size);
    let target_size = base_size + random_padding;
    
    // Create padded message
    let mut padded = Vec::with_capacity(target_size);
    padded.extend_from_slice(message);
    
    // Add length as a prefix
    let len_bytes = (message.len() as u32).to_be_bytes();
    
    // Add padding
    let padding_size = target_size - message.len() - len_bytes.len();
    let mut padding = vec![0u8; padding_size];
    thread_rng().fill(&mut padding[..]);
    
    // Combine everything
    let mut envelope = Vec::with_capacity(target_size + len_bytes.len());
    envelope.extend_from_slice(&len_bytes);
    envelope.extend_from_slice(message);
    envelope.extend_from_slice(&padding);
    
    envelope
}

/// Extract message from padded envelope
pub fn extract_from_envelope(envelope: &[u8]) -> Result<Vec<u8>, String> {
    if envelope.len() < 4 {
        return Err("Invalid envelope format: too short".to_string());
    }
    
    // Extract length prefix
    let msg_len = u32::from_be_bytes([
        envelope[0], envelope[1], envelope[2], envelope[3]
    ]) as usize;
    
    // Validate length
    if envelope.len() < 4 + msg_len {
        return Err("Invalid envelope format: corrupt length".to_string());
    }
    
    // Extract actual message
    Ok(envelope[4..4+msg_len].to_vec())
}

/// Generate a decoy message to add cover traffic
pub fn generate_decoy_message(size_range: (usize, usize)) -> Vec<u8> {
    let size = thread_rng().gen_range(size_range.0..size_range.1);
    let mut decoy = vec![0u8; size];
    thread_rng().fill(&mut decoy[..]);
    decoy
}

/// Encrypt data with key
fn encrypt_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
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
fn decrypt_data(key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
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

/// Obfuscate message timing to prevent traffic analysis
pub fn add_timing_jitter(base_delay_ms: u64) -> u64 {
    let jitter_factor = thread_rng().gen_range(80..120) as f64 / 100.0;
    (base_delay_ms as f64 * jitter_factor) as u64
}

/// Create a unique connection identifier that doesn't reveal client identity
pub fn create_connection_id(public_key_hash: &[u8]) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let mut hasher = Sha3_256::new();
    hasher.update(public_key_hash);
    hasher.update(timestamp.to_be_bytes());
    
    let random_bytes = thread_rng().gen::<[u8; 8]>();
    hasher.update(&random_bytes);
    
    hex::encode(&hasher.finalize()[0..16]) // Use first 16 bytes (32 hex chars)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_blind_token() {
        let token = b"original-token-data";
        let context = b"topic-context";
        
        let blinded = blind_token(token, context);
        
        // Blinded token should be 32 bytes (SHA-256 output)
        assert_eq!(blinded.len(), 32);
        
        // Same inputs should produce same output
        let blinded2 = blind_token(token, context);
        assert_eq!(blinded, blinded2);
        
        // Different context should produce different output
        let blinded3 = blind_token(token, b"different-context");
        assert_ne!(blinded, blinded3);
    }
    
    #[test]
    fn test_metadata_encryption() {
        let key = [1u8; 32]; // Test key
        let sender = "sender-fingerprint";
        let recipient = "recipient-fingerprint";
        let timestamp = 12345678;
        
        let encrypted = encrypt_metadata(sender, recipient, timestamp, &key).unwrap();
        let (dec_sender, dec_recipient, dec_timestamp) = decrypt_metadata(&encrypted, &key).unwrap();
        
        assert_eq!(sender, dec_sender);
        assert_eq!(recipient, dec_recipient);
        assert_eq!(timestamp, dec_timestamp);
    }
    
    #[test]
    fn test_padded_envelope() {
        let message = b"This is a test message";
        let block_size = 16;
        
        let envelope = create_padded_envelope(message, block_size);
        
        // Envelope should be larger than original message
        assert!(envelope.len() > message.len());
        
        // Extract should recover original message
        let extracted = extract_from_envelope(&envelope).unwrap();
        assert_eq!(extracted, message);
    }
    
    #[test]
    fn test_timing_jitter() {
        let base_delay = 100;
        
        // Test multiple times to ensure variability
        let mut delays = Vec::new();
        for _ in 0..100 {
            delays.push(add_timing_jitter(base_delay));
        }
        
        // Delays should vary
        assert!(delays.iter().min() != delays.iter().max());
        
        // Delays should be within range
        for delay in delays {
            assert!(delay >= 80 && delay <= 120);
        }
    }
}