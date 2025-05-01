// server/src/topic.rs
// Enhanced topic system for anonymous messaging

use actix_web::web;
use log::{debug, error, info, warn};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha3_256};
use sqlx::PgPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashSet;

use crate::db;
use crate::error::ServerError;
use crate::models::{Topic, TopicMessage};

// Maximum topic message size allowed (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

// Default message expiry time if not specified (7 days)
const DEFAULT_EXPIRY_SECONDS: u64 = 7 * 24 * 60 * 60;

// Maximum topic subscribers allowed
const MAX_TOPIC_SUBSCRIBERS: usize = 1000;

// Topic types
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum TopicType {
    Public,     // Anyone can subscribe
    Private,    // Need invitation
    Ephemeral,  // Short-lived, auto-deleted
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicMetadata {
    pub id: String,
    pub topic_type: TopicType,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub subscriber_count: usize,
    pub message_count: usize,
    pub max_message_size: usize,
    pub requires_auth: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscriptionToken {
    pub token: Vec<u8>,
    pub topic_id: Vec<u8>,
    pub expires_at: u64,
    pub capabilities: u8, // Bitfield for subscriber capabilities (read/write)
}

// Create a new anonymous topic
pub async fn create_topic(
    pool: &PgPool,
    topic_type: TopicType,
    creator_token: Option<&[u8]>,
    expiry_seconds: Option<u64>,
    max_subscribers: Option<usize>,
    requires_auth: bool,
) -> Result<String, ServerError> {
    info!("Creating new topic of type: {:?}", topic_type);
    
    // Generate random topic ID with high entropy
    let mut topic_id = [0u8; 32];
    thread_rng().fill(&mut topic_id);
    
    // Calculate expiry timestamp if needed
    let expiry_timestamp = match topic_type {
        TopicType::Ephemeral => {
            let now = SystemTime::now();
            let now_secs = now.duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Default to 24 hours for ephemeral topics if not specified
            let expiry = expiry_seconds.unwrap_or(24 * 60 * 60);
            Some(now_secs + expiry)
        },
        _ => expiry_seconds.map(|secs| {
            let now = SystemTime::now();
            let now_secs = now.duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now_secs + secs
        }),
    };
    
    // Set maximum subscribers (with reasonable default and upper limit)
    let max_subs = max_subscribers.unwrap_or(100).min(MAX_TOPIC_SUBSCRIBERS);
    
    // Create the topic in the database
    db::create_topic(
        pool,
        &topic_id,
        &topic_type.to_string(),
        expiry_timestamp,
        max_subs as i32,
        requires_auth,
    ).await?;
    
    // If creator token is provided, automatically make them the admin
    if let Some(token) = creator_token {
        let admin_capabilities = 0b111; // Read, write, admin
        
        // Generate blinded token to prevent correlation
        let blinded_token = blind_token(token, &topic_id);
        
        // Generate some minimal routing data (normally this would be encrypted)
        let routing_data = b"creator-admin".to_vec();
        
        // Add creator as subscriber with admin privileges
        db::subscribe_to_topic(
            pool,
            &topic_id,
            &blinded_token,
            &routing_data,
            admin_capabilities,
        ).await?;
    }
    
    // Return topic ID as hex
    let topic_id_hex = hex::encode(&topic_id);
    info!("Topic created with ID: {}", topic_id_hex);
    
    Ok(topic_id_hex)
}

// Subscribe to a topic
pub async fn subscribe_to_topic(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
    routing_data: &[u8],
    capabilities: Option<u8>,
) -> Result<(), ServerError> {
    info!("Processing subscription request for topic: {}", hex::encode(topic_id));
    
    // Check if topic exists
    let topic = match db::get_topic(pool, topic_id).await? {
        Some(t) => t,
        None => {
            return Err(ServerError::NotFoundError {
                resource: format!("Topic not found: {}", hex::encode(topic_id)),
            });
        }
    };
    
    // Check if topic requires authentication and validate if needed
    if topic.requires_auth {
        // In a real implementation, we would validate authentication here
        // For now, we just accept the token as is
        debug!("Topic requires authentication - validation not implemented");
    }
    
    // Check if topic is at subscriber limit
    let subscriber_count = db::get_topic_subscriber_count(pool, topic_id).await?;
    if subscriber_count >= topic.max_subscribers as usize {
        return Err(ServerError::BadRequestError {
            message: format!("Topic has reached maximum subscriber limit ({})", 
                           topic.max_subscribers),
        });
    }
    
    // Generate blinded token to prevent correlation
    let blinded_token = blind_token(subscriber_token, topic_id);
    
    // Set default capabilities if not provided (read-only)
    let caps = capabilities.unwrap_or(0b001);
    
    // Add subscription
    match db::subscribe_to_topic(pool, topic_id, &blinded_token, routing_data, caps).await {
        Ok(()) => {
            info!("Subscription successful");
            Ok(())
        },
        Err(e) => {
            error!("Failed to subscribe to topic: {:?}", e);
            Err(e)
        }
    }
}

// Unsubscribe from a topic
pub async fn unsubscribe_from_topic(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
) -> Result<bool, ServerError> {
    info!("Processing unsubscription request for topic: {}", hex::encode(topic_id));
    
    // Generate blinded token to prevent correlation
    let blinded_token = blind_token(subscriber_token, topic_id);
    
    // Remove subscription
    let success = db::unsubscribe_from_topic(pool, topic_id, &blinded_token).await?;
    
    if success {
        info!("Unsubscription successful");
    } else {
        warn!("Subscription not found for unsubscription request");
    }
    
    Ok(success)
}

// Publish a message to a topic
pub async fn publish_to_topic(
    pool: &PgPool,
    topic_id: &[u8],
    publisher_token: &[u8],
    encrypted_content: &[u8],
    expiry_seconds: Option<u64>,
) -> Result<String, ServerError> {
    info!("Publishing message to topic: {}", hex::encode(topic_id));
    
    // Validate message size
    if encrypted_content.len() > MAX_MESSAGE_SIZE {
        return Err(ServerError::BadRequestError {
            message: format!("Message too large: {} bytes (max: {} bytes)", 
                           encrypted_content.len(), MAX_MESSAGE_SIZE),
        });
    }
    
    // Check if topic exists
    let topic = match db::get_topic(pool, topic_id).await? {
        Some(t) => t,
        None => {
            return Err(ServerError::NotFoundError {
                resource: format!("Topic not found: {}", hex::encode(topic_id)),
            });
        }
    };
    
    // Check if publisher has write access
    let blinded_token = blind_token(publisher_token, topic_id);
    let subscriber = db::get_subscriber(pool, topic_id, &blinded_token).await?;
    
    let has_write_access = match subscriber {
        Some(sub) => (sub.capabilities & 0b010) != 0, // Check write bit
        None => false,
    };
    
    if !has_write_access && topic.requires_auth {
        return Err(ServerError::ForbiddenError {
            message: "No write access to this topic".to_string(),
        });
    }
    
    // Set expiry time within allowed limits
    let expiry = expiry_seconds.unwrap_or(DEFAULT_EXPIRY_SECONDS);
    
    // Generate random message ID
    let message_id = thread_rng().gen::<[u8; 32]>();
    
    // Create HMAC of content to ensure integrity
    let mut hasher = Sha256::new();
    hasher.update(&message_id);
    hasher.update(topic_id);
    hasher.update(encrypted_content);
    let hmac = hasher.finalize().to_vec();
    
    // Store the message
    db::store_topic_message(
        pool,
        topic_id,
        &message_id,
        encrypted_content,
        &hmac,
        expiry,
    ).await?;
    
    // Return message ID as hex
    let message_id_hex = hex::encode(&message_id);
    info!("Topic message stored with ID: {}", message_id_hex);
    
    Ok(message_id_hex)
}

// Get messages from a topic
pub async fn get_topic_messages(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
    limit: Option<usize>,
    since: Option<u64>,
) -> Result<Vec<TopicMessage>, ServerError> {
    info!("Fetching messages for topic: {}", hex::encode(topic_id));
    
    // Check if topic exists
    if !db::topic_exists(pool, topic_id).await? {
        return Err(ServerError::NotFoundError {
            resource: format!("Topic not found: {}", hex::encode(topic_id)),
        });
    }
    
    // Generate blinded token to prevent correlation
    let blinded_token = blind_token(subscriber_token, topic_id);
    
    // Check if user is subscribed
    let subscriber = db::get_subscriber(pool, topic_id, &blinded_token).await?;
    
    let has_read_access = match subscriber {
        Some(sub) => (sub.capabilities & 0b001) != 0, // Check read bit
        None => false,
    };
    
    if !has_read_access {
        return Err(ServerError::ForbiddenError {
            message: "Not subscribed to this topic".to_string(),
        });
    }
    
    // Get messages from database
    let effective_limit = limit.unwrap_or(20).min(100);
    let messages = db::get_topic_messages(pool, topic_id, effective_limit, since).await?;
    
    if !messages.is_empty() {
        info!("Retrieved {} topic messages", messages.len());
    } else {
        debug!("No topic messages available");
    }
    
    // Mark messages as delivered for this subscriber
    for message in &messages {
        let message_id = hex::decode(&message.id).unwrap_or_default();
        db::mark_topic_message_delivered(pool, &message_id, &blinded_token).await?;
    }
    
    Ok(messages)
}

// Get list of topics
pub async fn list_topics(
    pool: &PgPool,
    only_public: bool,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<Vec<Topic>, ServerError> {
    info!("Listing topics (public_only={})", only_public);
    
    // Set reasonable limits
    let effective_limit = limit.unwrap_or(20).min(100);
    let effective_offset = offset.unwrap_or(0);
    
    // Get topics from database
    let topics = db::list_topics(pool, only_public, effective_limit, effective_offset).await?;
    
    if !topics.is_empty() {
        info!("Retrieved {} topics", topics.len());
    } else {
        debug!("No topics available");
    }
    
    Ok(topics)
}

// Get topic metadata
pub async fn get_topic_metadata(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: Option<&[u8]>,
) -> Result<TopicMetadata, ServerError> {
    info!("Fetching metadata for topic: {}", hex::encode(topic_id));
    
    // Get topic information
    let topic = match db::get_topic(pool, topic_id).await? {
        Some(t) => t,
        None => {
            return Err(ServerError::NotFoundError {
                resource: format!("Topic not found: {}", hex::encode(topic_id)),
            });
        }
    };
    
    // Get subscriber count
    let subscriber_count = db::get_topic_subscriber_count(pool, topic_id).await?;
    
    // Get message count
    let message_count = db::get_topic_message_count(pool, topic_id).await?;
    
    // Check if requester is subscribed (to show admin-only information)
    let is_admin = if let Some(token) = subscriber_token {
        let blinded_token = blind_token(token, topic_id);
        let subscriber = db::get_subscriber(pool, topic_id, &blinded_token).await?;
        
        match subscriber {