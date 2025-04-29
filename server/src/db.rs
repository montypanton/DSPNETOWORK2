use log::{debug, error, info};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPool, Row};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::error::ServerError;
use crate::models::{Message, PreKeyBundle, Topic};

// Calculate hash from public keys
pub fn calculate_key_hash(
    ed25519_key: &[u8],
    x25519_key: &[u8],
    kyber_key: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ed25519_key);
    hasher.update(x25519_key);
    hasher.update(kyber_key);
    hasher.finalize().to_vec()
}

// Store public keys in database
pub async fn store_public_keys(
    pool: &PgPool,
    public_key_hash: &[u8],
    ed25519_public_key: &[u8],
    x25519_public_key: &[u8],
    kyber_public_key: &[u8],
    connection_token: &str,
) -> Result<(), ServerError> {
    info!("Storing public keys for hash: {}", hex::encode(public_key_hash));

    // Convert connection token to UUID
    let token_uuid = Uuid::parse_str(connection_token)
        .map_err(|e| ServerError::BadRequestError {
            message: format!("Invalid connection token: {}", e),
        })?;

    // Check if key already exists
    let existing = sqlx::query("SELECT public_key_hash FROM public_keys WHERE public_key_hash = $1")
        .bind(public_key_hash)
        .fetch_optional(pool)
        .await?;

    if existing.is_some() {
        // Update existing record
        sqlx::query(
            "UPDATE public_keys 
             SET ed25519_public_key = $2, 
                 x25519_public_key = $3, 
                 kyber_public_key = $4, 
                 connection_token = $5,
                 last_active = NOW()
             WHERE public_key_hash = $1"
        )
        .bind(public_key_hash)
        .bind(ed25519_public_key)
        .bind(x25519_public_key)
        .bind(kyber_public_key)
        .bind(token_uuid)
        .execute(pool)
        .await?;

        info!("Updated public keys for existing hash");
    } else {
        // Insert new record
        sqlx::query(
            "INSERT INTO public_keys 
             (public_key_hash, ed25519_public_key, x25519_public_key, kyber_public_key, connection_token, last_active) 
             VALUES ($1, $2, $3, $4, $5, NOW())"
        )
        .bind(public_key_hash)
        .bind(ed25519_public_key)
        .bind(x25519_public_key)
        .bind(kyber_public_key)
        .bind(token_uuid)
        .execute(pool)
        .await?;

        info!("Inserted new public keys record");
    }

    Ok(())
}

// Verify connection token
pub async fn verify_connection_token(
    pool: &PgPool,
    token: &str,
) -> Result<Vec<u8>, ServerError> {
    debug!("Verifying connection token: {}", token);

    // Parse token as UUID
    let token_uuid = Uuid::parse_str(token)
        .map_err(|_| ServerError::AuthenticationError)?;

    // Look up public key hash by token
    let result = sqlx::query("SELECT public_key_hash FROM public_keys WHERE connection_token = $1")
        .bind(token_uuid)
        .fetch_optional(pool)
        .await?;

    match result {
        Some(record) => {
            debug!("Token verified successfully");
            // Update last active timestamp
            sqlx::query("UPDATE public_keys SET last_active = NOW() WHERE connection_token = $1")
                .bind(token_uuid)
                .execute(pool)
                .await?;

            Ok(record.get("public_key_hash"))
        }
        None => {
            error!("Invalid connection token");
            Err(ServerError::AuthenticationError)
        }
    }
}

// Store prekeys
pub async fn store_prekeys(
    pool: &PgPool,
    public_key_hash: &[u8],
    prekeys: &[PreKeyBundle],
) -> Result<usize, ServerError> {
    info!("Storing {} prekeys for hash: {}", prekeys.len(), hex::encode(public_key_hash));

    let mut count = 0;

    // Start a transaction
    let mut tx = pool.begin().await?;

    for prekey in prekeys {
        // Check if this key_id already exists for this public key
        let existing = sqlx::query(
            "SELECT id FROM prekeys 
             WHERE public_key_hash = $1 AND key_id = $2"
        )
        .bind(public_key_hash)
        .bind(&prekey.key_id)
        .fetch_optional(&mut tx)
        .await?;

        if existing.is_none() {
            // Insert new prekey
            sqlx::query(
                "INSERT INTO prekeys 
                 (public_key_hash, key_id, x25519_public_key, kyber_public_key, is_used) 
                 VALUES ($1, $2, $3, $4, FALSE)"
            )
            .bind(public_key_hash)
            .bind(&prekey.key_id)
            .bind(&prekey.x25519)
            .bind(&prekey.kyber.0)
            .execute(&mut tx)
            .await?;

            count += 1;
        }
    }

    // Commit the transaction
    tx.commit().await?;

    info!("Stored {} new prekeys", count);
    Ok(count)
}

// Get prekeys for a public key
pub async fn get_prekeys(
    pool: &PgPool,
    public_key_hash: &[u8],
    limit: i32,
) -> Result<Vec<PreKeyBundle>, ServerError> {
    info!("Fetching prekeys for hash: {}", hex::encode(public_key_hash));

    // Get prekeys that haven't been used yet
    let rows = sqlx::query(
        "SELECT key_id, x25519_public_key, kyber_public_key 
         FROM prekeys 
         WHERE public_key_hash = $1 AND is_used = FALSE 
         LIMIT $2"
    )
    .bind(public_key_hash)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        info!("No prekeys available for hash: {}", hex::encode(public_key_hash));
        return Err(ServerError::NotFoundError {
            resource: format!("No prekeys found for {}", hex::encode(public_key_hash)),
        });
    }

    // Start a transaction to mark prekeys as used
    let mut tx = pool.begin().await?;

    let mut prekeys = Vec::with_capacity(rows.len());

    for row in rows {
        let key_id: Vec<u8> = row.get("key_id");
        let x25519: Vec<u8> = row.get("x25519_public_key");
        let kyber: Vec<u8> = row.get("kyber_public_key");
        
        prekeys.push(PreKeyBundle {
            key_id,
            x25519,
            kyber: crate::models::KyberPublicKey(kyber),
        });
        
        sqlx::query(
            "UPDATE prekeys SET is_used = TRUE WHERE public_key_hash = $1 AND key_id = $2"
        )
        .bind(public_key_hash)
        .bind(&prekeys.last().unwrap().key_id)
        .execute(&mut tx)
        .await?;
    }

    // Commit the transaction
    tx.commit().await?;

    info!("Returning {} prekeys", prekeys.len());
    Ok(prekeys)
}

// Store a message
pub async fn store_message(
    pool: &PgPool,
    message_id: &[u8],
    recipient_key_hash: &[u8],
    encrypted_content: &[u8],
    expiry_seconds: u64,
) -> Result<(), ServerError> {
    info!(
        "Storing message {} for recipient: {}",
        hex::encode(message_id),
        hex::encode(recipient_key_hash)
    );

    // Calculate expiry timestamp
    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(expiry_seconds);
    let expiry_timestamp = expiry
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Insert the message
    sqlx::query(
        "INSERT INTO pending_messages 
         (id, recipient_key_hash, encrypted_content, created_at, expiry, is_delivered) 
         VALUES ($1, $2, $3, NOW(), to_timestamp($4), FALSE)"
    )
    .bind(message_id)
    .bind(recipient_key_hash)
    .bind(encrypted_content)
    .bind(expiry_timestamp as f64)
    .execute(pool)
    .await?;

    info!("Message stored successfully");
    Ok(())
}

// Get pending messages for a recipient
pub async fn get_pending_messages(
    pool: &PgPool,
    public_key_hash: &[u8],
) -> Result<Vec<Message>, ServerError> {
    info!("Fetching pending messages for: {}", hex::encode(public_key_hash));

    // Get messages that haven't been delivered
    let rows = sqlx::query(
        "SELECT id, recipient_key_hash, encrypted_content, 
         extract(epoch from expiry)::bigint as expiry_epoch
         FROM pending_messages 
         WHERE recipient_key_hash = $1 AND is_delivered = FALSE 
         ORDER BY created_at ASC"
    )
    .bind(public_key_hash)
    .fetch_all(pool)
    .await?;

    // Convert rows to Message objects
    let mut messages = Vec::with_capacity(rows.len());
    
    for row in rows {
        let id: Vec<u8> = row.get("id");
        let recipient_key_hash: Vec<u8> = row.get("recipient_key_hash");
        let encrypted_content: Vec<u8> = row.get("encrypted_content");
        let expiry_epoch: i64 = row.get("expiry_epoch");
        
        messages.push(Message {
            id: hex::encode(&id),
            recipient_key_hash: hex::encode(&recipient_key_hash),
            encrypted_content,
            expiry: expiry_epoch as u64,
        });
    }

    info!("Found {} pending messages", messages.len());
    Ok(messages)
}

// Mark a message as delivered
pub async fn mark_message_delivered(
    pool: &PgPool,
    message_id: &[u8],
) -> Result<bool, ServerError> {
    info!("Marking message as delivered: {}", hex::encode(message_id));

    // Update message status
    let result = sqlx::query("UPDATE pending_messages SET is_delivered = TRUE WHERE id = $1")
        .bind(message_id)
        .execute(pool)
        .await?;

    if result.rows_affected() > 0 {
        info!("Message marked as delivered");
        Ok(true)
    } else {
        info!("Message not found");
        Ok(false)
    }
}

// Create a new topic
pub async fn create_topic(pool: &PgPool) -> Result<String, ServerError> {
    info!("Creating new topic");

    // Generate random topic hash
    let mut topic_hash = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut topic_hash);

    // Insert the topic
    sqlx::query("INSERT INTO topics (id, created_at) VALUES ($1, NOW())")
        .bind(&topic_hash[..])
        .execute(pool)
        .await?;

    let hash_hex = hex::encode(&topic_hash);
    info!("Topic created with hash: {}", hash_hex);
    Ok(hash_hex)
}

// List available topics
pub async fn list_topics(pool: &PgPool) -> Result<Vec<Topic>, ServerError> {
    info!("Listing available topics");

    // Get all topics
    let rows = sqlx::query("SELECT id, extract(epoch from created_at)::bigint as created_at_epoch FROM topics ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;

    // Convert rows to Topic objects
    let mut topics = Vec::with_capacity(rows.len());
    
    for row in rows {
        let id: Vec<u8> = row.get("id");
        let created_at_epoch: i64 = row.get("created_at_epoch");
        
        topics.push(Topic {
            hash: hex::encode(&id),
            created_at: created_at_epoch as u64,
        });
    }

    info!("Found {} topics", topics.len());
    Ok(topics)
}

// Subscribe to a topic
pub async fn subscribe_to_topic(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
    routing_data: &[u8],
) -> Result<(), ServerError> {
    info!(
        "Adding subscription for topic: {}",
        hex::encode(topic_id)
    );

    // Check if topic exists
    let topic_exists = sqlx::query("SELECT 1 FROM topics WHERE id = $1")
        .bind(topic_id)
        .fetch_optional(pool)
        .await?;

    if topic_exists.is_none() {
        return Err(ServerError::NotFoundError {
            resource: format!("Topic not found: {}", hex::encode(topic_id)),
        });
    }

    // Check if already subscribed
    let existing = sqlx::query(
        "SELECT 1 FROM topic_subscriptions WHERE topic_id = $1 AND subscriber_token = $2"
    )
    .bind(topic_id)
    .bind(subscriber_token)
    .fetch_optional(pool)
    .await?;

    if existing.is_some() {
        // Update subscription
        sqlx::query(
            "UPDATE topic_subscriptions SET routing_data = $3 WHERE topic_id = $1 AND subscriber_token = $2"
        )
        .bind(topic_id)
        .bind(subscriber_token)
        .bind(routing_data)
        .execute(pool)
        .await?;

        info!("Updated existing subscription");
    } else {
        // Insert new subscription
        sqlx::query(
            "INSERT INTO topic_subscriptions (topic_id, subscriber_token, routing_data) VALUES ($1, $2, $3)"
        )
        .bind(topic_id)
        .bind(subscriber_token)
        .bind(routing_data)
        .execute(pool)
        .await?;

        info!("Added new subscription");
    }

    Ok(())
}

// Unsubscribe from a topic
pub async fn unsubscribe_from_topic(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
) -> Result<bool, ServerError> {
    info!(
        "Removing subscription for topic: {}",
        hex::encode(topic_id)
    );

    // Delete subscription
    let result = sqlx::query(
        "DELETE FROM topic_subscriptions WHERE topic_id = $1 AND subscriber_token = $2"
    )
    .bind(topic_id)
    .bind(subscriber_token)
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        info!("Subscription removed");
        Ok(true)
    } else {
        info!("Subscription not found");
        Ok(false)
    }
}

// Store a topic message
pub async fn store_topic_message(
    pool: &PgPool,
    topic_id: &[u8],
    message_id: &[u8],
    encrypted_content: &[u8],
    expiry_seconds: u64,
) -> Result<(), ServerError> {
    info!(
        "Storing message {} for topic: {}",
        hex::encode(message_id),
        hex::encode(topic_id)
    );

    // Calculate expiry timestamp
    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(expiry_seconds);
    let expiry_timestamp = expiry
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Start a transaction
    let mut tx = pool.begin().await?;

    // Insert the message
    sqlx::query(
        "INSERT INTO topic_messages 
         (id, topic_id, encrypted_content, posted_at, expiry) 
         VALUES ($1, $2, $3, NOW(), to_timestamp($4))"
    )
    .bind(message_id)
    .bind(topic_id)
    .bind(encrypted_content)
    .bind(expiry_timestamp as f64)
    .execute(&mut tx)
    .await?;

    // Get subscribers for this topic
    let subscribers = sqlx::query(
        "SELECT subscriber_token FROM topic_subscriptions WHERE topic_id = $1"
    )
    .bind(topic_id)
    .fetch_all(&mut tx)
    .await?;

    // Insert delivery records for each subscriber
    for subscriber in subscribers {
        let subscriber_token: Vec<u8> = subscriber.get("subscriber_token");
        
        sqlx::query(
            "INSERT INTO message_delivery (message_id, recipient_token, is_delivered) VALUES ($1, $2, FALSE)"
        )
        .bind(message_id)
        .bind(&subscriber_token)
        .execute(&mut tx)
        .await?;
    }

    // Commit the transaction
    tx.commit().await?;

    info!("Topic message stored successfully");
    Ok(())
}