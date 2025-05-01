// src/utils/validation.rs
// Validation utilities for SecNet

use log::{debug, error, warn};
use regex::Regex;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use lazy_static::lazy_static;

lazy_static! {
    // Regex patterns for validation
    static ref FINGERPRINT_PATTERN: Regex = Regex::new(r"^[0-9a-f]{64}$").unwrap();
    static ref TOKEN_PATTERN: Regex = Regex::new(r"^[0-9a-f]{64}$").unwrap();
    static ref URL_PATTERN: Regex = Regex::new(
        r"^(https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d{1,5})?(/.*)?$"
    ).unwrap();
}

/// Validate a fingerprint format
pub fn validate_fingerprint(fingerprint: &str) -> bool {
    FINGERPRINT_PATTERN.is_match(fingerprint)
}

/// Validate a connection token format
pub fn validate_token(token: &str) -> bool {
    TOKEN_PATTERN.is_match(token)
}

/// Validate a server URL format
pub fn validate_server_url(url: &str) -> bool {
    URL_PATTERN.is_match(url)
}

/// Validate a message size
pub fn validate_message_size(content: &[u8], max_size: usize) -> bool {
    content.len() <= max_size
}

/// Validate a file path
pub fn validate_file_path(path: &Path) -> bool {
    // Check if path exists
    if !path.exists() {
        return false;
    }
    
    // Check if path is a file
    if !path.is_file() {
        return false;
    }
    
    // Check if file is readable
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.len() > 0,
        Err(_) => false,
    }
}

/// Validate a directory path
pub fn validate_directory_path(path: &Path) -> bool {
    // Check if path exists
    if !path.exists() {
        return false;
    }
    
    // Check if path is a directory
    if !path.is_dir() {
        return false;
    }
    
    // Check if directory is writable by creating a test file
    let test_file = path.join(".secnet_test_write");
    let write_result = std::fs::write(&test_file, b"test");
    if write_result.is_err() {
        return false;
    }
    
    // Clean up test file
    let _ = std::fs::remove_file(test_file);
    
    true
}

/// Validate message expiry time
pub fn validate_expiry_time(expiry_seconds: u64, min_expiry: u64, max_expiry: u64) -> u64 {
    expiry_seconds.max(min_expiry).min(max_expiry)
}

/// Validate if a timestamp is in the future
pub fn validate_future_timestamp(timestamp: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    timestamp > now
}

/// Validate a topic hash format
pub fn validate_topic_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate a message ID format
pub fn validate_message_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Sanitize a string for logging or display
pub fn sanitize_string(input: &str, max_length: usize) -> String {
    let trimmed = input.trim();
    
    // Limit length
    let limited = if trimmed.len() > max_length {
        format!("{}...", &trimmed[0..max_length])
    } else {
        trimmed.to_string()
    };
    
    // Replace control characters with spaces
    limited.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Validate user input for command line arguments
pub fn validate_user_input(input: &str) -> bool {
    // Check for potentially malicious characters
    if input.contains(';') || input.contains('|') || input.contains('&') || 
       input.contains('`') || input.contains('$') || input.contains('\\') {
        return false;
    }
    
    // Check for reasonable length
    if input.len() > 1024 {
        return false;
    }
    
    // Check for control characters
    if input.chars().any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r') {
        return false;
    }
    
    true
}

/// Validate peer certificate fingerprint
pub fn validate_peer_certificate(fingerprint: &str, stored_fingerprint: &str) -> bool {
    if !validate_fingerprint(fingerprint) || !validate_fingerprint(stored_fingerprint) {
        return false;
    }
    
    // Compare fingerprints in constant time to prevent timing attacks
    if fingerprint.len() != stored_fingerprint.len() {
        return false;
    }
    
    let mut result = 0;
    for (a, b) in fingerprint.bytes().zip(stored_fingerprint.bytes()) {
        result |= a ^ b;
    }
    
    result == 0
}

/// Validate a blinded topic token
pub fn validate_blinded_token(token: &[u8]) -> bool {
    // Check token length (SHA-256 output is 32 bytes)
    if token.len() != 32 {
        return false;
    }
    
    // Check if token has sufficient entropy
    // For a cryptographic token, every byte should be used
    let mut byte_usage = [0u8; 256];
    for &byte in token {
        byte_usage[byte as usize] += 1;
    }
    
    // At least 32 different byte values should be used in a good token
    let unique_bytes = byte_usage.iter().filter(|&&count| count > 0).count();
    unique_bytes >= 16 // Minimum threshold for entropy
}

/// Validate topic access permissions
pub fn validate_topic_access(capabilities: u8, required_access: u8) -> bool {
    (capabilities & required_access) == required_access
}

/// Validate if IP address is within allowed ranges
pub fn validate_ip_address(ip: &str) -> bool {
    // This is a placeholder - in a real implementation, you would check against
    // allowed IP ranges, rate limiting databases, etc.
    
    // Simple check for private IP ranges
    let is_private = ip.starts_with("10.") || 
                     ip.starts_with("172.16.") || 
                     ip.starts_with("192.168.") || 
                     ip == "127.0.0.1";
    
    // For this example, we'll allow all non-private IPs
    !is_private
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_fingerprint() {
        assert!(validate_fingerprint("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        assert!(!validate_fingerprint("0123456789abcdef")); // Too short
        assert!(!validate_fingerprint("0123456789abcdefg")); // Invalid character 'g'
    }
    
    #[test]
    fn test_validate_token() {
        assert!(validate_token("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        assert!(!validate_token("not-a-valid-token"));
    }
    
    #[test]
    fn test_validate_server_url() {
        assert!(validate_server_url("https://example.com"));
        assert!(validate_server_url("http://sub.example.com:8080"));
        assert!(validate_server_url("example.com"));
        assert!(!validate_server_url("not a url"));
    }
    
    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("  test  ", 10), "test");
        assert_eq!(sanitize_string("abcdefghijklmnop", 10), "abcdefghij...");
        assert_eq!(sanitize_string("test\x00data", 10), "test data");
    }
    
    #[test]
    fn test_validate_user_input() {
        assert!(validate_user_input("normal text input"));
        assert!(!validate_user_input("rm -rf /; echo hacked"));
        assert!(!validate_user_input("$(touch file)"));
    }
    
    #[test]
    fn test_validate_peer_certificate() {
        let fp1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let fp2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let fp3 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        
        assert!(validate_peer_certificate(fp1, fp2));
        assert!(!validate_peer_certificate(fp1, fp3));
    }
}