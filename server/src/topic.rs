// server/src/topic.rs
use actix_web::HttpResponse;
use log::{debug, error, info, warn};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::ServerError;
use crate::models::{Topic, TopicMessage};

// Topic types
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum TopicType {
    Public,     // Anyone can subscribe
    Private,    // Need invitation
    Ephemeral,  // Short-lived, auto-deleted
}

// Convert TopicType to string for database storage
impl ToString for TopicType {
    fn to_string(&self) -> String {
        match self {
            TopicType::Public => "Public".to_string(),
            TopicType::Private => "Private".to_string(),
            TopicType::Ephemeral => "Ephemeral".to_string(),
        }
    }
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

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicSubscription {
    pub topic_id: String,
    pub subscriber_token: Vec<u8>,
    pub routing_data: Vec<u8>,
    pub capabilities: u8,
    pub join_time: u64,
    pub last_active: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicInvitation {
    pub topic_id: String,
    pub invitation_token: Vec<u8>,
    pub capabilities: u8,
    pub created_at: u64,
    pub expires_at: u64,
    pub is_used: bool,
}

// Create a new anonymous topic
pub async fn create_topic(
    pool: &PgPool,
    topic_type: Option<TopicType>,
    creator_token: Option<&[u8]>,
    expiry_seconds: Option<u64>,
    max_subscribers: Option<usize>,
    requires_auth: bool,
) -> Result<String, ServerError> {
    info!("Creating new topic of type: {:?}", topic_type);
    
    // Generate random topic ID with high entropy
    let mut topic_id = [0u8; 32];
    thread_rng().fill(&mut topic_id);
    
    // Create the topic in the database (simplified implementation)
    crate::db::create_topic(pool).await
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
    let topic = match crate::db::get_topic(pool, topic_id).await? {
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
    let subscriber_count = crate::db::get_topic_subscriber_count(pool, topic_id).await?;
    
    // Setting a reasonable max subscriber limit
    let max_subscribers = 100; // Default limit
    if subscriber_count >= max_subscribers {
        return Err(ServerError::BadRequestError {
            message: format!("Topic has reached maximum subscriber limit ({})", 
                           max_subscribers),
        });
    }
    
    // Generate blinded token to prevent correlation
    let blinded_token = blind_token(subscriber_token, topic_id);
    
    // Set default capabilities if not provided (read-only)
    let caps = capabilities.unwrap_or(0b001);
    
    // Add subscription
    match crate::db::subscribe_to_topic(pool, topic_id, &blinded_token, routing_data, caps).await {
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
    let success = crate::db::unsubscribe_from_topic(pool, topic_id, &blinded_token).await?;
    
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
    
    // Maximum message size (10MB)
    const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
    
    // Validate message size
    if encrypted_content.len() > MAX_MESSAGE_SIZE {
        return Err(ServerError::BadRequestError {
            message: format!("Message too large: {} bytes (max: {} bytes)", 
                           encrypted_content.len(), MAX_MESSAGE_SIZE),
        });
    }
    
    // Check if topic exists
    let topic = match crate::db::get_topic(pool, topic_id).await? {
        Some(t) => t,
        None => {
            return Err(ServerError::NotFoundError {
                resource: format!("Topic not found: {}", hex::encode(topic_id)),
            });
        }
    };
    
    // Check if publisher has write access
    let blinded_token = blind_token(publisher_token, topic_id);
    let subscriber = crate::db::get_subscriber(pool, topic_id, &blinded_token).await?;
    
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
    // Default to 7 days for topic messages
    const DEFAULT_EXPIRY_SECONDS: u64 = 7 * 24 * 60 * 60;
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
    crate::db::store_topic_message(
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
    if !crate::db::topic_exists(pool, topic_id).await? {
        return Err(ServerError::NotFoundError {
            resource: format!("Topic not found: {}", hex::encode(topic_id)),
        });
    }
    
    // Generate blinded token to prevent correlation
    let blinded_token = blind_token(subscriber_token, topic_id);
    
    // Check if user is subscribed
    let subscriber = crate::db::get_subscriber(pool, topic_id, &blinded_token).await?;
    
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
    let messages = crate::db::get_topic_messages(pool, topic_id, effective_limit, since).await?;
    
    if !messages.is_empty() {
        info!("Retrieved {} topic messages", messages.len());
    } else {
        debug!("No topic messages available");
    }
    
    // Mark messages as delivered for this subscriber
    for message in &messages {
        let message_id = hex::decode(&message.id).unwrap_or_default();
        crate::db::mark_topic_message_delivered(pool, &message_id, &blinded_token).await?;
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
    let topics = crate::db::list_topics(pool, only_public, effective_limit, effective_offset).await?;
    
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
    let topic = match crate::db::get_topic(pool, topic_id).await? {
        Some(t) => t,
        None => {
            return Err(ServerError::NotFoundError {
                resource: format!("Topic not found: {}", hex::encode(topic_id)),
            });
        }
    };
    
    // Get subscriber count
    let subscriber_count = crate::db::get_topic_subscriber_count(pool, topic_id).await?;
    
    // Get message count
    let message_count = crate::db::get_topic_message_count(pool, topic_id).await?;
    
    // Check if requester is subscribed (to show admin-only information)
    let _is_admin = if let Some(token) = subscriber_token {
        let blinded_token = blind_token(token, topic_id);
        let subscriber = crate::db::get_subscriber(pool, topic_id, &blinded_token).await?;
        
        match subscriber {
            Some(sub) => (sub.capabilities & 0b100) != 0, // Check admin bit
            None => false,
        }
    } else {
        false
    };
    
    // Create new metadata response with updated counts
    let mut metadata = topic;
    metadata.subscriber_count = subscriber_count;
    metadata.message_count = message_count;
    
    Ok(metadata)
}

// Delete a topic (admin only)
pub async fn delete_topic(
    pool: &PgPool,
    topic_id: &[u8],
    admin_token: &[u8],
) -> Result<(), ServerError> {
    info!("Request to delete topic: {}", hex::encode(topic_id));
    
    // Check if requester is an admin
    let blinded_token = blind_token(admin_token, topic_id);
    let subscriber = crate::db::get_subscriber(pool, topic_id, &blinded_token).await?;
    
    let has_admin_access = match subscriber {
        Some(sub) => (sub.capabilities & 0b100) != 0, // Check admin bit
        None => false,
    };
    
    if !has_admin_access {
        return Err(ServerError::ForbiddenError {
            message: "No admin access to this topic".to_string(),
        });
    }
    
    // Delete the topic and all related data
    crate::db::delete_topic(pool, topic_id).await?;
    
    info!("Topic deleted: {}", hex::encode(topic_id));
    Ok(())
}

// Helper function to blind tokens
pub fn blind_token(token: &[u8], context: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token);
    hasher.update(context);
    hasher.update(b"SecNetBlinding");
    hasher.finalize().to_vec()
}

// Purge expired topics and messages (for maintenance)
pub async fn purge_expired_data(pool: &PgPool) -> Result<(usize, usize), ServerError> {
    info!("Running expired data purge");
    
    // Delete expired topics
    let topics_deleted = crate::db::delete_expired_topics(pool).await?;
    
    // Delete expired messages
    let messages_deleted = crate::db::delete_expired_topic_messages(pool).await?;
    
    // Delete expired invitations (not implemented yet)
    let _invitations_deleted = crate::db::delete_expired_invitations(pool).await?;
    
    info!("Purged {} expired topics and {} expired messages", 
         topics_deleted, messages_deleted);
    
    Ok((topics_deleted, messages_deleted))
}

// Check for topic health (subscriber count, message activity)
pub async fn check_topic_health(
    pool: &PgPool,
    topic_id: &[u8],
) -> Result<TopicHealthReport, ServerError> {
    info!("Checking health for topic: {}", hex::encode(topic_id));
    
    // Get topic information
    let topic = match crate::db::get_topic(pool, topic_id).await? {
        Some(t) => t,
        None => {
            return Err(ServerError::NotFoundError {
                resource: format!("Topic not found: {}", hex::encode(topic_id)),
            });
        }
    };
    
    // Get current subscriber count
    let subscriber_count = crate::db::get_topic_subscriber_count(pool, topic_id).await?;
    
    // Get message activity in the last day
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let day_ago = now - 24 * 60 * 60;
    
    let recent_message_count = crate::db::get_topic_message_count_since(pool, topic_id, day_ago).await?;
    
    // Check if topic is soon to expire
    let is_expiring_soon = match topic.expires_at {
        Some(expiry) => {
            // Check if expiring within next 48 hours
            expiry < now + 48 * 60 * 60
        },
        None => false,
    };
    
    // Create health report
    let health = TopicHealthReport {
        id: hex::encode(topic_id),
        subscriber_count,
        recent_message_count,
        inactive: recent_message_count == 0,
        is_expiring_soon,
        expiry: topic.expires_at,
        created_at: topic.created_at,
    };
    
    Ok(health)
}

#[derive(Debug, Serialize)]
pub struct TopicHealthReport {
    pub id: String,
    pub subscriber_count: usize,
    pub recent_message_count: usize,
    pub inactive: bool,
    pub is_expiring_soon: bool,
    pub expiry: Option<u64>,
    pub created_at: u64,
}

// Add admin capabilities to the server admin interface
#[derive(Debug, Serialize, Deserialize)]
pub enum TopicAdminAction {
    ExtendExpiry { new_expiry_seconds: u64 },
    IncreaseCapacity { new_max_subscribers: usize },
    RemoveUser { blinded_token: Vec<u8> },
    ChangeVisibility { new_type: TopicType },
    PurgeMessages { older_than_seconds: Option<u64> },
}

pub async fn admin_topic_action(
    pool: &PgPool,
    topic_id: &[u8],
    admin_token: &[u8], 
    action: TopicAdminAction,
) -> Result<(), ServerError> {
    info!("Admin action on topic: {}", hex::encode(topic_id));
    
    // Verify admin rights
    let blinded_token = blind_token(admin_token, topic_id);
    let subscriber = crate::db::get_subscriber(pool, topic_id, &blinded_token).await?;
    
    let has_admin_access = match subscriber {
        Some(sub) => (sub.capabilities & 0b100) != 0, // Check admin bit
        None => false,
    };
    
    if !has_admin_access {
        return Err(ServerError::ForbiddenError {
            message: "No admin access to this topic".to_string(),
        });
    }
    
    // Perform the requested action
    match action {
        TopicAdminAction::ExtendExpiry { new_expiry_seconds } => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let new_expiry = now + new_expiry_seconds;
            
            crate::db::update_topic_expiry(pool, topic_id, new_expiry).await?;
            info!("Topic expiry extended: {}", hex::encode(topic_id));
        },
        
        TopicAdminAction::IncreaseCapacity { new_max_subscribers } => {
            // Enforce maximum limit
            let capped_max = new_max_subscribers.min(1000);
            
            crate::db::update_topic_capacity(pool, topic_id, capped_max as i32).await?;
            info!("Topic capacity increased to {}: {}", capped_max, hex::encode(topic_id));
        },
        
        TopicAdminAction::RemoveUser { blinded_token } => {
            // Remove user from topic
            crate::db::force_unsubscribe_from_topic(pool, topic_id, &blinded_token).await?;
            info!("User removed from topic: {}", hex::encode(topic_id));
        },
        
        TopicAdminAction::ChangeVisibility { new_type } => {
            // Update topic type
            crate::db::update_topic_type(pool, topic_id, &new_type.to_string()).await?;
            info!("Topic type changed to {:?}: {}", new_type, hex::encode(topic_id));
        },
        
        TopicAdminAction::PurgeMessages { older_than_seconds } => {
            let cutoff_time = if let Some(seconds) = older_than_seconds {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now - seconds
            } else {
                0 // Delete all messages if no time specified
            };
            
            crate::db::delete_topic_messages_before(pool, topic_id, cutoff_time).await?;
            info!("Topic messages purged: {}", hex::encode(topic_id));
        },
    }
    
    Ok(())
}