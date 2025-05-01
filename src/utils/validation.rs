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
    let limited = if trimmed.len()