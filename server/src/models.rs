use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

// Authentication models
#[derive(Debug, Serialize, Deserialize)]
pub struct AnnouncementRequest {
    pub ed25519_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub kyber_public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnnouncementResponse {
    pub connection_token: String,
    pub public_key_hash: String,
}

// Prekey models
#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub key_id: Vec<u8>,
    pub x25519: Vec<u8>,
    pub kyber: KyberPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KyberPublicKey(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeysUploadRequest {
    pub public_key_hash: String,
    pub prekeys: Vec<PreKeyBundle>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeysResponse {
    pub status: String,
    pub count: usize,
}

// Message models
#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub recipient_key_hash: String,
    pub encrypted_content: Vec<u8>,
    pub expiry: Option<u64>, // Optional TTL in seconds
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub recipient_key_hash: String,
    pub encrypted_content: Vec<u8>,
    pub expiry: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMessagesResponse {
    pub messages: Vec<Message>,
    pub more_available: bool,
}

// Topic models
#[derive(Debug, Serialize, Deserialize)]
pub struct Topic {
    pub hash: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicCreateResponse {
    pub topic_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicListResponse {
    pub topics: Vec<Topic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicSubscribeRequest {
    pub topic_hash: String,
    pub subscriber_token: Vec<u8>,
    pub routing_data: Vec<u8>, // Encrypted routing information
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTopicMessageRequest {
    pub topic_hash: String,
    pub encrypted_content: Vec<u8>,
    pub expiry: Option<u64>, // Optional TTL in seconds
}

// Helper function to get current timestamp
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}