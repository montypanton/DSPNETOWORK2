// server/src/message.rs
// Enhanced secure message handling with improved metadata protection

use actix_web::web;
use log::{debug, error, info, warn};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db;
use crate::error::ServerError;
use crate::models::Message;

// Maximum message size allowed (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

// Default message expiry time if not specified (24 hours)
const DEFAULT_EXPIRY_SECONDS: u64 = 86400;

// Maximum message expiry time (30 days)
const MAX_EXPIRY_SECONDS: u64 = 30 * 24 * 60 * 60;

// Minimum message expiry time (1 hour)
const MIN_EXPIRY_SECONDS: u64 = 3600;

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub id: String,
    pub recipient_hash: String,
    pub size: usize,
    pub encrypted: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub priority: u8,
    pub delivery_attempts: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageContainer {
    pub metadata: MessageMetadata,
    pub encrypted_content: Vec<u8>,
    pub hmac: Vec<u8>,
}

pub async fn store_message(
    pool: &PgPool,
    recipient_key_hash: &[u8],
    encrypted_content: &[u8],
    expiry_seconds: Option<u64>,
    priority: Option<u8>,
) -> Result<String, ServerError> {
    // Validate message size
    if encrypted_content.len() > MAX_MESSAGE_SIZE {
        return Err(ServerError::BadRequestError {
            message: format!("Message too large: {} bytes (max: {} bytes)", 
                              encrypted_content.len(), MAX_MESSAGE_SIZE),
        });
    }
    
    // Set expiry time within allowed limits
    let expiry = expiry_seconds.unwrap_or(DEFAULT_EXPIRY_SECONDS)
        .min(MAX_EXPIRY_SECONDS)
        .max(MIN_EXPIRY_SECONDS);
    
    // Generate a random message ID
    let message_id = thread_rng().gen::<[u8; 32]>();
    
    // Create HMAC of content to ensure integrity
    let mut hasher = Sha256::new();
    hasher.update(&message_id);
    hasher.update(recipient_key_hash);
    hasher.update(encrypted_content);
    let hmac = hasher.finalize().to_vec();
    
    // Calculate expiry timestamp
    let now = SystemTime::now();
    let now_secs = now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expiry_timestamp = now_secs + expiry;
    
    // Store the message
    db::store_message(
        pool,
        &message_id,
        recipient_key_hash,
        encrypted_content,
        &hmac,
        expiry,
        priority.unwrap_or(1),
    ).await?;
    
    // Return message ID as hex
    let message_id_hex = hex::encode(&message_id);
    info!("Message stored with ID: {}", message_id_hex);
    
    Ok(message_id_hex)
}

pub async fn get_pending_messages(
    pool: &PgPool,
    recipient_key_hash: &[u8],
    limit: Option<usize>,
) -> Result<Vec<Message>, ServerError> {
    // Set reasonable default and maximum limits
    let effective_limit = limit.unwrap_or(20).min(100);
    
    // Get messages from database
    let messages = db::get_pending_messages(pool, recipient_key_hash, effective_limit).await?;
    
    if !messages.is_empty() {
        info!("Retrieved {} pending messages for recipient", messages.len());
    } else {
        debug!("No pending messages for recipient");
    }
    
    Ok(messages)
}

pub async fn acknowledge_message(
    pool: &PgPool,
    message_id: &[u8],
    recipient_key_hash: &[u8],
) -> Result<bool, ServerError> {
    // To improve privacy, we verify the recipient actually owns the message
    let message_exists = db::verify_message_recipient(pool, message_id, recipient_key_hash).await?;
    
    if !message_exists {
        return Err(ServerError::NotFoundError {
            resource: format!("Message {}", hex::encode(message_id)),
        });
    }
    
    // Mark the message as delivered
    let success = db::mark_message_delivered(pool, message_id).await?;
    
    if success {
        info!("Message {} marked as delivered", hex::encode(message_id));
    } else {
        warn!("Failed to mark message {} as delivered", hex::encode(message_id));
    }
    
    Ok(success)
}

// Periodic cleanup of expired messages
pub async fn cleanup_expired_messages(pool: &PgPool) -> Result<usize, ServerError> {
    info!("Running expired message cleanup");
    
    let deleted_count = db::delete_expired_messages(pool).await?;
    
    if deleted_count > 0 {
        info!("Deleted {} expired messages", deleted_count);
    } else {
        debug!("No expired messages to delete");
    }
    
    Ok(deleted_count)
}

// Additional utility functions for message processing

// Obfuscate metadata for better privacy
pub fn obfuscate_metadata(message_id: &[u8], recipient_hash: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message_id);
    hasher.update(recipient_hash);
    hasher.update(b"SecNetObfuscation");
    hasher.finalize().to_vec()
}

// Generate a secure notification token that doesn't reveal the recipient
pub fn generate_notification_token(recipient_hash: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(recipient_hash);
    // Add a timestamp to make tokens unique even for the same recipient
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    hasher.update(&timestamp.to_be_bytes());
    hex::encode(&hasher.finalize()[0..16]) // Use first 16 bytes for shorter token
}

// Verify message integrity
pub fn verify_message_integrity(
    message_id: &[u8],
    recipient_hash: &[u8],
    content: &[u8],
    stored_hmac: &[u8],
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(message_id);
    hasher.update(recipient_hash);
    hasher.update(content);
    let calculated_hmac = hasher.finalize();
    
    // Compare HMACs in constant time to prevent timing attacks
    if stored_hmac.len() != calculated_hmac.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (a, b) in stored_hmac.iter().zip(calculated_hmac.iter()) {
        result |= a ^ b;
    }
    
    result == 0
}

// Calculate message storage statistics
pub async fn get_message_statistics(pool: &PgPool) -> Result<MessageStats, ServerError> {
    let stats = db::get_message_stats(pool).await?;
    
    Ok(stats)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageStats {
    pub total_pending: usize,
    pub total_delivered: usize,
    pub expired_last_day: usize,
    pub delivered_last_day: usize,
    pub avg_message_size: usize,
    pub total_storage_bytes: usize,
}