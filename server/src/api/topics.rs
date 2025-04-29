use actix_web::{get, post, web, HttpResponse, HttpRequest};
use log::info;
use sqlx::PgPool;
use uuid::Uuid;
use sha2::{Sha256, Digest};

use crate::db;
use crate::error::ServerError;
use crate::models::{SendTopicMessageRequest, SendMessageResponse, TopicCreateResponse, TopicListResponse, TopicSubscribeRequest};

// Helper function to extract token from Authorization header
fn extract_token(req: &HttpRequest) -> Result<&str, ServerError> {
    let auth_header = req.headers().get("Authorization")
        .ok_or(ServerError::AuthenticationError)?;
        
    let auth_str = auth_header.to_str()
        .map_err(|_| ServerError::AuthenticationError)?;
        
    if !auth_str.starts_with("Bearer ") {
        return Err(ServerError::AuthenticationError);
    }
    
    Ok(auth_str.trim_start_matches("Bearer ").trim())
}

// Create a new topic
#[post("/topics")]
pub async fn create_topic(
    pool: web::Data<PgPool>,
    req: HttpRequest,
) -> Result<HttpResponse, ServerError> {
    info!("Received topic creation request");
    
    // Extract token from Authorization header
    let token = extract_token(&req)?;
    
    // Verify token
    db::verify_connection_token(&pool, token).await?;
    
    // Create topic
    let topic_hash = db::create_topic(&pool).await?;
    
    info!("Topic created with hash: {}", topic_hash);
    
    // Return success response
    Ok(HttpResponse::Created().json(TopicCreateResponse {
        topic_hash,
    }))
}

// List topics
#[get("/topics")]
pub async fn list_topics(
    pool: web::Data<PgPool>,
    req: HttpRequest,
) -> Result<HttpResponse, ServerError> {
    info!("Received topic list request");
    
    // Extract token from Authorization header
    let token = extract_token(&req)?;
    
    // Verify token
    db::verify_connection_token(&pool, token).await?;
    
    // Get topics
    let topics = db::list_topics(&pool).await?;
    
    info!("Found {} topics", topics.len());
    
    // Return topics
    Ok(HttpResponse::Ok().json(TopicListResponse {
        topics,
    }))
}

// Subscribe to a topic
#[post("/topics/{topic_hash}/subscribe")]
pub async fn subscribe_topic(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    path: web::Path<String>,
    topic_req: web::Json<TopicSubscribeRequest>,
) -> Result<HttpResponse, ServerError> {
    let topic_hash_hex = path.into_inner();
    info!("Received subscription request for topic: {}", topic_hash_hex);
    
    // Extract token from Authorization header
    let token = extract_token(&req)?;
    
    // Verify token
    db::verify_connection_token(&pool, token).await?;
    
    // Convert hex to bytes
    let topic_id = match hex::decode(&topic_hash_hex) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid topic hash format".to_string(),
            });
        }
    };
    
    // Verify topic hash matches
    if topic_req.topic_hash != topic_hash_hex {
        return Err(ServerError::BadRequestError {
            message: "Topic hash in body doesn't match URL".to_string(),
        });
    }
    
    // Subscribe to topic
    db::subscribe_to_topic(&pool, &topic_id, &topic_req.subscriber_token, &topic_req.routing_data).await?;
    
    info!("Subscription successful");
    
    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "subscribed"
    })))
}

// Unsubscribe from a topic
#[post("/topics/{topic_hash}/unsubscribe")]
pub async fn unsubscribe_topic(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, ServerError> {
    let topic_hash_hex = path.into_inner();
    info!("Received unsubscribe request for topic: {}", topic_hash_hex);
    
    // Extract token from Authorization header
    let token = extract_token(&req)?;
    
    // Verify token and get public key hash
    let public_key_hash = db::verify_connection_token(&pool, token).await?;
    
    // Convert hex to bytes
    let topic_id = match hex::decode(&topic_hash_hex) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid topic hash format".to_string(),
            });
        }
    };
    
    // Create subscriber token from public key hash (simplified)
    let mut hasher = Sha256::new();
    hasher.update(&public_key_hash);
    let subscriber_token = hasher.finalize().to_vec();
    
    // Unsubscribe from topic
    let success = db::unsubscribe_from_topic(&pool, &topic_id, &subscriber_token).await?;
    
    if success {
        info!("Unsubscription successful");
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "unsubscribed"
        })))
    } else {
        info!("Subscription not found");
        Err(ServerError::NotFoundError {
            resource: format!("Subscription for topic {}", topic_hash_hex),
        })
    }
}

// Publish to a topic
#[post("/topics/{topic_hash}/messages")]
pub async fn publish_topic(
    pool: web::Data<PgPool>,
    req: HttpRequest,
    path: web::Path<String>,
    topic_req: web::Json<SendTopicMessageRequest>,
) -> Result<HttpResponse, ServerError> {
    let topic_hash_hex = path.into_inner();
    info!("Received publish request for topic: {}", topic_hash_hex);
    
    // Extract token from Authorization header
    let token = extract_token(&req)?;
    
    // Verify token
    db::verify_connection_token(&pool, token).await?;
    
    // Verify topic hash matches
    if topic_req.topic_hash != topic_hash_hex {
        return Err(ServerError::BadRequestError {
            message: "Topic hash in body doesn't match URL".to_string(),
        });
    }
    
    // Convert hex to bytes
    let topic_id = match hex::decode(&topic_hash_hex) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid topic hash format".to_string(),
            });
        }
    };
    
    // Generate random message ID
    let message_id = Uuid::new_v4().as_bytes().to_vec();
    
    // Default expiry to 24 hours if not specified
    let expiry = topic_req.expiry.unwrap_or(86400);
    
    // Store topic message
    db::store_topic_message(
        &pool,
        &topic_id,
        &message_id,
        &topic_req.encrypted_content,
        expiry,
    ).await?;
    
    info!("Topic message stored successfully with ID: {}", hex::encode(&message_id));
    
    // Return success response
    Ok(HttpResponse::Created().json(SendMessageResponse {
        message_id: hex::encode(&message_id),
        status: "sent".to_string(),
    }))
}