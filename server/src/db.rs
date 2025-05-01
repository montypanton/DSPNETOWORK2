// server/src/db.rs
use log::{debug, info, trace};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::error::ServerError;
use crate::models::{
    KyberPublicKey, Message, PreKeyBundle, Topic, TopicMessage,
};

// Store a message with improved integrity protection
pub async fn store_message(
    pool: &PgPool,
    message_id: &[u8],
    recipient_key_hash: &[u8],
    encrypted_content: &[u8],
    hmac: &[u8],
    expiry_seconds: u64,
    priority: u8,
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

    // Insert the message with added integrity protection
    sqlx::query!(
        "INSERT INTO pending_messages 
         (id, recipient_key_hash, encrypted_content, hmac, created_at, expiry, is_delivered, priority, delivery_attempts) 
         VALUES ($1, $2, $3, $4, NOW(), to_timestamp($5), FALSE, $6, 0)",
        message_id,
        recipient_key_hash,
        encrypted_content,
        hmac,
        expiry_timestamp as f64,
        priority as i16
    )
    .execute(pool)
    .await?;

    info!("Message stored successfully");
    Ok(())
}

// Calculate a hash of the public keys for identity
pub async fn calculate_key_hash(
    ed25519_public_key: &[u8],
    x25519_public_key: &[u8],
    kyber_public_key: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ed25519_public_key);
    hasher.update(x25519_public_key);
    hasher.update(kyber_public_key);
    hasher.finalize().to_vec()
}

// Store public keys and connection token
pub async fn store_public_keys(
    pool: &PgPool,
    public_key_hash: &[u8],
    ed25519_public_key: &[u8],
    x25519_public_key: &[u8],
    kyber_public_key: &[u8],
    connection_token: &str,
) -> Result<(), ServerError> {
    info!(
        "Storing public keys for hash: {}",
        hex::encode(public_key_hash)
    );

    let token_uuid = match Uuid::parse_str(connection_token) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid connection token format".to_string(),
            })
        }
    };

    // Try to insert, if exists update the token
    sqlx::query!(
        "INSERT INTO public_keys 
         (public_key_hash, ed25519_public_key, x25519_public_key, kyber_public_key, connection_token, last_active) 
         VALUES ($1, $2, $3, $4, $5, NOW())
         ON CONFLICT (public_key_hash) 
         DO UPDATE SET connection_token = $5, last_active = NOW(), connection_count = COALESCE(public_keys.connection_count, 0) + 1",
        public_key_hash,
        ed25519_public_key,
        x25519_public_key,
        kyber_public_key,
        token_uuid
    )
    .execute(pool)
    .await?;

    info!("Public keys stored successfully");
    Ok(())
}

// Verify a connection token and return associated public key hash
pub async fn verify_connection_token(pool: &PgPool, token: &str) -> Result<Vec<u8>, ServerError> {
    debug!("Verifying connection token: {}", token);

    let token_uuid = match Uuid::parse_str(token) {
        Ok(uuid) => uuid,
        Err(_) => {
            debug!("Invalid token format: {}", token);
            return Err(ServerError::AuthenticationError);
        }
    };

    // Look up the token and update last_active
    let result = sqlx::query!(
        "UPDATE public_keys
         SET last_active = NOW()
         WHERE connection_token = $1
         RETURNING public_key_hash",
        token_uuid
    )
    .fetch_optional(pool)
    .await?;

    match result {
        Some(record) => {
            trace!("Token verified successfully");
            Ok(record.public_key_hash.to_vec())
        }
        None => {
            debug!("Invalid token, no matching record: {}", token);
            Err(ServerError::AuthenticationError)
        }
    }
}

// Store prekeys for a user
pub async fn store_prekeys(
    pool: &PgPool,
    public_key_hash: &[u8],
    prekeys: &[PreKeyBundle],
) -> Result<usize, ServerError> {
    info!(
        "Storing {} prekeys for hash: {}",
        prekeys.len(),
        hex::encode(public_key_hash)
    );

    let mut count = 0;

    for prekey in prekeys {
        // Check if this prekey ID already exists for this public key
        let existing = sqlx::query!(
            "SELECT id FROM prekeys WHERE public_key_hash = $1 AND key_id = $2",
            public_key_hash,
            prekey.key_id
        )
        .fetch_optional(pool)
        .await?;

        if existing.is_some() {
            debug!("Prekey already exists, skipping");
            continue;
        }

        // Insert the prekey
        sqlx::query!(
            "INSERT INTO prekeys 
             (public_key_hash, key_id, x25519_public_key, kyber_public_key, is_used)
             VALUES ($1, $2, $3, $4, FALSE)",
            public_key_hash,
            &prekey.key_id,
            &prekey.x25519,
            &prekey.kyber.0 // Access the inner Vec<u8>
        )
        .execute(pool)
        .await?;

        count += 1;
    }

    info!("Stored {} prekeys successfully", count);
    Ok(count)
}

// Get prekeys for a user
pub async fn get_prekeys(
    pool: &PgPool,
    public_key_hash: &[u8],
    limit: usize,
) -> Result<Vec<PreKeyBundle>, ServerError> {
    info!(
        "Fetching up to {} prekeys for hash: {}",
        limit,
        hex::encode(public_key_hash)
    );

    let rows = sqlx::query!(
        "SELECT key_id, x25519_public_key, kyber_public_key 
         FROM prekeys 
         WHERE public_key_hash = $1 AND is_used = FALSE
         LIMIT $2",
        public_key_hash,
        limit as i64
    )
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        debug!("No prekeys available");
        return Ok(Vec::new());
    }

    // Mark these prekeys as used
    let prekey_ids: Vec<Vec<u8>> = rows.iter().map(|row| row.key_id.clone()).collect();

    sqlx::query!(
        "UPDATE prekeys SET is_used = TRUE WHERE public_key_hash = $1 AND key_id = ANY($2)",
        public_key_hash,
        &prekey_ids
    )
    .execute(pool)
    .await?;

    // Convert to PreKeyBundle objects
    let prekeys: Vec<PreKeyBundle> = rows
        .into_iter()
        .map(|row| PreKeyBundle {
            key_id: row.key_id,
            x25519: row.x25519_public_key,
            kyber: KyberPublicKey(row.kyber_public_key),
        })
        .collect();

    info!("Fetched {} prekeys", prekeys.len());
    Ok(prekeys)
}

// Get pending messages for a recipient
pub async fn get_pending_messages(
    pool: &PgPool,
    recipient_key_hash: &[u8],
    limit: Option<usize>,
) -> Result<Vec<Message>, ServerError> {
    let effective_limit = limit.unwrap_or(20).min(100) as i64;

    info!(
        "Fetching up to {} pending messages for recipient: {}",
        effective_limit,
        hex::encode(recipient_key_hash)
    );

    let rows = sqlx::query!(
        "SELECT id, encrypted_content, 
         EXTRACT(EPOCH FROM expiry)::bigint as expiry_ts
         FROM pending_messages
         WHERE recipient_key_hash = $1 AND is_delivered = FALSE
         ORDER BY priority DESC, created_at ASC
         LIMIT $2",
        recipient_key_hash,
        effective_limit
    )
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        debug!("No pending messages found");
        return Ok(Vec::new());
    }

    // Convert to Message objects
    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        let expiry_timestamp = row.expiry_ts.unwrap_or(0) as u64;

        messages.push(Message {
            id: hex::encode(&row.id),
            recipient_key_hash: hex::encode(recipient_key_hash),
            encrypted_content: row.encrypted_content,
            expiry: expiry_timestamp,
        });
    }

    info!("Fetched {} pending messages", messages.len());
    Ok(messages)
}

// Verify message recipient for additional security
pub async fn verify_message_recipient(
    pool: &PgPool,
    message_id: &[u8],
    recipient_key_hash: &[u8],
) -> Result<bool, ServerError> {
    debug!(
        "Verifying recipient {} for message {}",
        hex::encode(recipient_key_hash),
        hex::encode(message_id)
    );

    let result = sqlx::query!(
        "SELECT COUNT(*) as count
         FROM pending_messages
         WHERE id = $1 AND recipient_key_hash = $2",
        message_id,
        recipient_key_hash
    )
    .fetch_one(pool)
    .await?;

    let exists = result.count.unwrap_or(0) > 0;
    debug!("Message recipient verification result: {}", exists);
    Ok(exists)
}

// Mark a message as delivered
pub async fn mark_message_delivered(
    pool: &PgPool,
    message_id: &[u8],
) -> Result<bool, ServerError> {
    debug!("Marking message as delivered: {}", hex::encode(message_id));

    let result = sqlx::query!(
        "UPDATE pending_messages
         SET is_delivered = TRUE
         WHERE id = $1 AND is_delivered = FALSE
         RETURNING id",
        message_id
    )
    .fetch_optional(pool)
    .await?;

    let success = result.is_some();
    if success {
        debug!("Message marked as delivered");
    } else {
        debug!("Message not found or already delivered");
    }

    Ok(success)
}

// Delete expired messages
pub async fn delete_expired_messages(pool: &PgPool) -> Result<usize, ServerError> {
    debug!("Deleting expired messages");

    let result = sqlx::query!(
        "DELETE FROM pending_messages
         WHERE expiry < NOW()
         RETURNING id"
    )
    .fetch_all(pool)
    .await?;

    let count = result.len();
    info!("Deleted {} expired messages", count);
    Ok(count)
}

// Get message statistics for monitoring
pub async fn get_message_stats(pool: &PgPool) -> Result<crate::message::MessageStats, ServerError> {
    debug!("Getting message statistics");

    // Get total pending and delivered counts
    let counts = sqlx::query!(
        "SELECT
            SUM(CASE WHEN is_delivered = FALSE THEN 1 ELSE 0 END) as pending_count,
            SUM(CASE WHEN is_delivered = TRUE THEN 1 ELSE 0 END) as delivered_count
         FROM pending_messages"
    )
    .fetch_one(pool)
    .await?;

    // Get expired and delivered in last day
    let day_stats = sqlx::query!(
        "SELECT
            SUM(CASE WHEN expiry < NOW() AND expiry > NOW() - INTERVAL '1 day' THEN 1 ELSE 0 END) as expired_count,
            SUM(CASE WHEN is_delivered = TRUE AND created_at > NOW() - INTERVAL '1 day' THEN 1 ELSE 0 END) as delivered_count
         FROM pending_messages"
    )
    .fetch_one(pool)
    .await?;

    // Get size statistics - handling NUMERIC type correctly
    let size_stats = sqlx::query!(
        "SELECT
            COALESCE(AVG(LENGTH(encrypted_content))::integer, 0) as avg_size,
            COALESCE(SUM(LENGTH(encrypted_content))::bigint, 0) as total_size
         FROM pending_messages"
    )
    .fetch_one(pool)
    .await?;

    // Convert to expected types
    let avg_size = size_stats.avg_size.unwrap_or(0) as usize;
    let total_size = size_stats.total_size.unwrap_or(0) as usize;

    Ok(crate::message::MessageStats {
        total_pending: counts.pending_count.unwrap_or(0) as usize,
        total_delivered: counts.delivered_count.unwrap_or(0) as usize,
        expired_last_day: day_stats.expired_count.unwrap_or(0) as usize,
        delivered_last_day: day_stats.delivered_count.unwrap_or(0) as usize,
        avg_message_size: avg_size,
        total_storage_bytes: total_size,
    })
}

// Create a new topic
pub async fn create_topic(pool: &PgPool) -> Result<String, ServerError> {
    debug!("Creating new topic");

    // Generate a random topic ID
    let topic_id = Uuid::new_v4().as_bytes().to_vec();

    // Insert the topic with minimal required fields
    sqlx::query!(
        "INSERT INTO topics (id, created_at)
         VALUES ($1, NOW())",
        topic_id
    )
    .execute(pool)
    .await?;

    // Return the topic hash as a hex string
    let topic_hash = hex::encode(&topic_id);
    info!("Topic created with hash: {}", topic_hash);
    Ok(topic_hash)
}

// List available topics
pub async fn list_topics(
    pool: &PgPool,
    only_public: bool,
    limit: usize,
    offset: usize,
) -> Result<Vec<Topic>, ServerError> {
    debug!("Listing topics, public_only={}", only_public);

    // Combined query with conditional filter
    let rows = sqlx::query!(
        r#"
        SELECT id, EXTRACT(EPOCH FROM created_at)::bigint as created_at
        FROM topics
        WHERE ($1 = false OR topic_type = 'Public' OR topic_type IS NULL)
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
        only_public,
        limit as i64,
        offset as i64
    )
    .fetch_all(pool)
    .await?;

    // Convert to model objects
    let topics: Vec<Topic> = rows  
    .into_iter()
    .map(|row| {
        let created_timestamp = row.created_at.unwrap_or(0) as u64;

        Topic {
            hash: hex::encode(&row.id),
            created_at: created_timestamp,
        }
    })
    .collect();

    debug!("Found {} topics", topics.len());
    Ok(topics)
}

// Get a specific topic
pub async fn get_topic(pool: &PgPool, topic_id: &[u8]) -> Result<Option<crate::topic::TopicMetadata>, ServerError> {
    debug!("Fetching topic: {}", hex::encode(topic_id));

    // Query with explicit timestamp conversion
    let row = sqlx::query!(
        "SELECT EXTRACT(EPOCH FROM created_at)::bigint as created_at
         FROM topics WHERE id = $1", 
        topic_id
    )
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        let created_timestamp = row.created_at.unwrap_or(0) as u64;

        Ok(Some(crate::topic::TopicMetadata {
            id: hex::encode(topic_id),
            topic_type: crate::topic::TopicType::Public, // Default to Public
            created_at: created_timestamp,
            expires_at: None,
            subscriber_count: 0, // Will be updated later
            message_count: 0,    // Will be updated later
            max_message_size: 10 * 1024 * 1024, // 10MB default
            requires_auth: false,
        }))
    } else {
        debug!("Topic not found");
        Ok(None)
    }
}

// Check if a topic exists
pub async fn topic_exists(pool: &PgPool, topic_id: &[u8]) -> Result<bool, ServerError> {
    debug!("Checking if topic exists: {}", hex::encode(topic_id));

    let result = sqlx::query!(
        "SELECT COUNT(*) as count FROM topics WHERE id = $1",
        topic_id
    )
    .fetch_one(pool)
    .await?;

    let exists = result.count.unwrap_or(0) > 0;
    debug!("Topic exists: {}", exists);
    Ok(exists)
}

// Subscribe to a topic
pub async fn subscribe_to_topic(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
    routing_data: &[u8],
    capabilities: u8,
) -> Result<(), ServerError> {
    debug!(
        "Subscribing to topic: {} with capabilities: {}",
        hex::encode(topic_id),
        capabilities
    );

    // Check if topic exists
    if !topic_exists(pool, topic_id).await? {
        return Err(ServerError::NotFoundError {
            resource: format!("Topic {}", hex::encode(topic_id)),
        });
    }

    // Insert or update subscription
    sqlx::query!(
        "INSERT INTO topic_subscriptions 
        (topic_id, subscriber_token, routing_data, capabilities) 
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (topic_id, subscriber_token) 
        DO UPDATE SET routing_data = $3, last_active = NOW(), capabilities = $4",
        topic_id,
        subscriber_token,
        routing_data,
        capabilities as i16
    )
    .execute(pool)
    .await?;

    debug!("Subscription successful");
    Ok(())
}

// Unsubscribe from a topic
pub async fn unsubscribe_from_topic(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
) -> Result<bool, ServerError> {
    debug!(
        "Unsubscribing from topic: {}",
        hex::encode(topic_id)
    );

    // Delete the subscription
    let result = sqlx::query!(
        "DELETE FROM topic_subscriptions
         WHERE topic_id = $1 AND subscriber_token = $2
         RETURNING id",
        topic_id,
        subscriber_token
    )
    .fetch_optional(pool)
    .await?;

    let success = result.is_some();
    if success {
        debug!("Unsubscription successful");
    } else {
        debug!("Subscription not found");
    }

    Ok(success)
}

// Force unsubscribe a user from a topic (admin function)
pub async fn force_unsubscribe_from_topic(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
) -> Result<bool, ServerError> {
    debug!(
        "Force unsubscribing from topic: {}",
        hex::encode(topic_id)
    );

    // Delete the subscription
    let result = sqlx::query!(
        "DELETE FROM topic_subscriptions
         WHERE topic_id = $1 AND subscriber_token = $2
         RETURNING id",
        topic_id,
        subscriber_token
    )
    .fetch_optional(pool)
    .await?;

    let success = result.is_some();
    if success {
        debug!("Force unsubscription successful");
    } else {
        debug!("Subscription not found");
    }

    Ok(success)
}

// Get subscriber information
pub async fn get_subscriber(
    pool: &PgPool,
    topic_id: &[u8],
    subscriber_token: &[u8],
) -> Result<Option<crate::topic::TopicSubscription>, ServerError> {
    debug!(
        "Getting subscriber for topic: {}",
        hex::encode(topic_id)
    );

    // Query with explicit timestamp conversion
    let row = sqlx::query!(
        "SELECT routing_data, capabilities, 
         EXTRACT(EPOCH FROM join_time)::bigint as join_time,
         EXTRACT(EPOCH FROM last_active)::bigint as last_active
         FROM topic_subscriptions
         WHERE topic_id = $1 AND subscriber_token = $2",
        topic_id,
        subscriber_token
    )
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        Ok(Some(crate::topic::TopicSubscription {
            topic_id: hex::encode(topic_id),
            subscriber_token: subscriber_token.to_vec(),
            routing_data: row.routing_data,
            capabilities: row.capabilities as u8,
            join_time: row.join_time.unwrap_or(0) as u64,
            last_active: row.last_active.unwrap_or(0) as u64,
        }))
    } else {
        Ok(None)
    }
}

// Get count of subscribers for a topic
pub async fn get_topic_subscriber_count(
    pool: &PgPool,
    topic_id: &[u8],
) -> Result<usize, ServerError> {
    debug!("Getting subscriber count for topic: {}", hex::encode(topic_id));

    let result = sqlx::query!(
        "SELECT COUNT(*) as count FROM topic_subscriptions WHERE topic_id = $1",
        topic_id
    )
    .fetch_one(pool)
    .await?;

    let count = result.count.unwrap_or(0) as usize;
    debug!("Topic has {} subscribers", count);
    Ok(count)
}

// Store a topic message
pub async fn store_topic_message(
    pool: &PgPool,
    topic_id: &[u8],
    message_id: &[u8],
    encrypted_content: &[u8],
    hmac: &[u8],
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

    // Insert the message
    sqlx::query!(
        "INSERT INTO topic_messages
         (id, topic_id, encrypted_content, hmac, posted_at, expiry)
         VALUES ($1, $2, $3, $4, NOW(), to_timestamp($5))",
        message_id,
        topic_id,
        encrypted_content,
        hmac,
        expiry_timestamp as f64
    )
    .execute(pool)
    .await?;

    // Create delivery tracking entries for each subscriber
    sqlx::query!(
        "INSERT INTO message_delivery (message_id, recipient_token, is_delivered)
         SELECT $1, subscriber_token, FALSE
         FROM topic_subscriptions
         WHERE topic_id = $2",
        message_id,
        topic_id
    )
    .execute(pool)
    .await?;

    info!("Topic message stored successfully");
    Ok(())
}

// Get messages for a topic
pub async fn get_topic_messages(
    pool: &PgPool,
    topic_id: &[u8],
    limit: usize,
    since: Option<u64>,
) -> Result<Vec<TopicMessage>, ServerError> {
    debug!("Getting messages for topic: {}, limit: {}", hex::encode(topic_id), limit);

    // Use a combined query with conditional filter
    let since_timestamp = since.unwrap_or(0) as f64;
    let rows = sqlx::query!(
        r#"
        SELECT id, encrypted_content, 
        EXTRACT(EPOCH FROM posted_at)::bigint as posted_at,
        EXTRACT(EPOCH FROM expiry)::bigint as expiry
        FROM topic_messages
        WHERE topic_id = $1 
        AND ($2 = 0 OR posted_at > to_timestamp($2))
        ORDER BY posted_at DESC
        LIMIT $3
        "#,
        topic_id,
        since_timestamp as i32,
        limit as i64
    )
    .fetch_all(pool)
    .await?;

    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        messages.push(TopicMessage {
            id: hex::encode(&row.id),
            topic_hash: hex::encode(topic_id),
            encrypted_content: row.encrypted_content,
            posted_at: row.posted_at.unwrap_or(0) as u64,
            expiry: row.expiry.unwrap_or(0) as u64,
        });
    }

    debug!("Found {} topic messages", messages.len());
    Ok(messages)
}

// Mark a topic message as delivered for a specific recipient
pub async fn mark_topic_message_delivered(
    pool: &PgPool,
    message_id: &[u8],
    subscriber_token: &[u8],
) -> Result<bool, ServerError> {
    debug!(
        "Marking topic message as delivered: {} for subscriber",
        hex::encode(message_id)
    );

    // Modified query to work with or without delivery_time
    let result = sqlx::query!(
        "UPDATE message_delivery
         SET is_delivered = TRUE, delivery_time = NOW()
         WHERE message_id = $1 AND recipient_token = $2 AND is_delivered = FALSE
         RETURNING id",
        message_id,
        subscriber_token
    )
    .fetch_optional(pool)
    .await?;

    let success = result.is_some();
    if success {
        debug!("Topic message marked as delivered");
    } else {
        debug!("Topic message delivery record not found");
    }

    Ok(success)
}

// Get message count for a topic
pub async fn get_topic_message_count(
    pool: &PgPool,
    topic_id: &[u8],
) -> Result<usize, ServerError> {
    debug!("Getting message count for topic: {}", hex::encode(topic_id));

    let result = sqlx::query!(
        "SELECT COUNT(*) as count FROM topic_messages WHERE topic_id = $1",
        topic_id
    )
    .fetch_one(pool)
    .await?;

    let count = result.count.unwrap_or(0) as usize;
    debug!("Topic has {} messages", count);
    Ok(count)
}

// Get message count for a topic since a specific time
pub async fn get_topic_message_count_since(
    pool: &PgPool,
    topic_id: &[u8],
    since: u64,
) -> Result<usize, ServerError> {
    debug!(
        "Getting message count for topic: {} since {}",
        hex::encode(topic_id),
        since
    );

    let result = sqlx::query!(
        "SELECT COUNT(*) as count 
         FROM topic_messages 
         WHERE topic_id = $1 AND posted_at > to_timestamp($2)",
        topic_id,
        since as f64
    )
    .fetch_one(pool)
    .await?;

    let count = result.count.unwrap_or(0) as usize;
    debug!("Topic has {} messages since timestamp", count);
    Ok(count)
}

// Create an invitation for a private topic (stub implementation)
pub async fn create_topic_invitation(
    _pool: &PgPool,
    _topic_id: &[u8],
    _invitation_token: &[u8],
    _capabilities: u8,
    _expiry: u64,
) -> Result<(), ServerError> {
    debug!("Topic invitation functionality not available");
    Ok(())
}

// Get a topic invitation (stub implementation)
pub async fn get_topic_invitation(
    _pool: &PgPool,
    _topic_id: &[u8],
    _invitation_token: &[u8],
) -> Result<Option<crate::topic::TopicInvitation>, ServerError> {
    debug!("Topic invitation functionality not available");
    Ok(None)
}

// Mark a topic invitation as used (stub implementation)
pub async fn mark_invitation_used(
    _pool: &PgPool,
    _topic_id: &[u8],
    _invitation_token: &[u8],
    _used_by: &[u8],
) -> Result<bool, ServerError> {
    debug!("Topic invitation functionality not available");
    Ok(false)
}

// Delete a topic and all related data
pub async fn delete_topic(
    pool: &PgPool,
    topic_id: &[u8],
) -> Result<(), ServerError> {
    debug!("Deleting topic: {}", hex::encode(topic_id));

    // Start a transaction
    let mut tx = pool.begin().await?;

    // Delete all message delivery records
    sqlx::query!(
        "DELETE FROM message_delivery
         WHERE message_id IN (SELECT id FROM topic_messages WHERE topic_id = $1)",
        topic_id
    )
    .execute(&mut tx)
    .await?;

    // Delete all messages
    sqlx::query!(
        "DELETE FROM topic_messages WHERE topic_id = $1",
        topic_id
    )
    .execute(&mut tx)
    .await?;

    // Delete all subscriptions
    sqlx::query!(
        "DELETE FROM topic_subscriptions WHERE topic_id = $1",
        topic_id
    )
    .execute(&mut tx)
    .await?;

    // Delete the topic itself
    sqlx::query!(
        "DELETE FROM topics WHERE id = $1",
        topic_id
    )
    .execute(&mut tx)
    .await?;

    // Commit the transaction
    tx.commit().await?;

    info!("Topic deleted successfully: {}", hex::encode(topic_id));
    Ok(())
}

// Delete expired topics (stub implementation)
pub async fn delete_expired_topics(
    _pool: &PgPool,
) -> Result<usize, ServerError> {
    debug!("Expired topics check skipped (feature not implemented)");
    Ok(0)
}

// Delete expired topic messages
pub async fn delete_expired_topic_messages(
    pool: &PgPool,
) -> Result<usize, ServerError> {
    debug!("Deleting expired topic messages");

    // Get expired message IDs
    let message_ids = sqlx::query!(
        "SELECT id FROM topic_messages WHERE expiry < NOW()"
    )
    .fetch_all(pool)
    .await?;

    if message_ids.is_empty() {
        return Ok(0);
    }

    // Start a transaction
    let mut tx = pool.begin().await?;

    let mut count = 0;
    
    // Delete related delivery records and messages one by one
    for row in &message_ids {
        // Delete delivery records first
        sqlx::query!(
            "DELETE FROM message_delivery WHERE message_id = $1",
            row.id
        )
        .execute(&mut tx)
        .await?;
        
        // Then delete the message
        let result = sqlx::query!(
            "DELETE FROM topic_messages WHERE id = $1",
            row.id
        )
        .execute(&mut tx)
        .await?;
        
        count += result.rows_affected() as usize;
    }

    // Commit the transaction
    tx.commit().await?;

    info!("Deleted {} expired topic messages", count);
    Ok(count)
}

// Delete expired invitations (stub implementation)
pub async fn delete_expired_invitations(
    _pool: &PgPool,
) -> Result<usize, ServerError> {
    debug!("Expired invitations check skipped (feature not implemented)");
    Ok(0)
}

// Delete topic messages before a certain time 
pub async fn delete_topic_messages_before(
    pool: &PgPool,
    topic_id: &[u8],
    timestamp: u64,
) -> Result<usize, ServerError> {
    debug!(
        "Deleting topic messages before timestamp: {} for topic: {}",
        timestamp,
        hex::encode(topic_id)
    );

    // Use a transaction to ensure consistency
    let mut tx = pool.begin().await?;
    
    // Combined query with conditional filter
    let message_ids = sqlx::query!(
        r#"
        SELECT id FROM topic_messages 
        WHERE topic_id = $1
        AND ($2 = 0 OR posted_at < to_timestamp($2))
        "#,
        topic_id,
        timestamp as f64
    )
    .fetch_all(&mut tx)
    .await?;

    if message_ids.is_empty() {
        return Ok(0);
    }
    
    let mut count = 0;
    
    // Delete related delivery records and messages one by one
    for row in &message_ids {
        // Delete delivery records first
        sqlx::query!(
            "DELETE FROM message_delivery WHERE message_id = $1",
            row.id
        )
        .execute(&mut tx)
        .await?;
        
        // Then delete the message
        let result = sqlx::query!(
            "DELETE FROM topic_messages WHERE id = $1",
            row.id
        )
        .execute(&mut tx)
        .await?;
        
        count += result.rows_affected() as usize;
    }

    // Commit the transaction
    tx.commit().await?;

    info!("Deleted {} topic messages", count);
    Ok(count)
}

// Update topic expiry (stub implementation)
pub async fn update_topic_expiry(
    _pool: &PgPool,
    topic_id: &[u8],
    _expiry: u64,
) -> Result<(), ServerError> {
    debug!(
        "Topic expiry update for topic: {} requested (not implemented)",
        hex::encode(topic_id)
    );
    Ok(())
}

// Update topic capacity (stub implementation)
pub async fn update_topic_capacity(
    _pool: &PgPool,
    topic_id: &[u8],
    _max_subscribers: i32,
) -> Result<(), ServerError> {
    debug!(
        "Topic capacity update for topic: {} requested (not implemented)",
        hex::encode(topic_id)
    );
    Ok(())
}

// Update topic type (stub implementation)
pub async fn update_topic_type(
    _pool: &PgPool,
    topic_id: &[u8],
    _topic_type: &str,
) -> Result<(), ServerError> {
    debug!(
        "Topic type update for topic: {} requested (not implemented)",
        hex::encode(topic_id)
    );
    Ok(())
}