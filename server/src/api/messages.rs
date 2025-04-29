use actix_web::{delete, get, post, web, HttpResponse};
use log::{debug, error, info};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db;
use crate::error::ServerError;
use crate::models::{FetchMessagesResponse, SendMessageRequest, SendMessageResponse};

// Send a message
#[post("/messages")]
pub async fn send_message(
    pool: web::Data<PgPool>,
    auth: web::Header<String>,
    req: web::Json<SendMessageRequest>,
) -> Result<HttpResponse, ServerError> {
    info!("Received message send request");
    
    // Extract token from Authorization header
    let token = auth.trim_start_matches("Bearer ").trim();
    
    // Verify token
    db::verify_connection_token(&pool, token).await?;
    
    // Generate random message ID
    let message_id = Uuid::new_v4().as_bytes().to_vec();
    
    // Convert hex to bytes
    let recipient_hash = match hex::decode(&req.recipient_key_hash) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid recipient key hash format".to_string(),
            });
        }
    };
    
    // Default expiry to 24 hours if not specified
    let expiry = req.expiry.unwrap_or(86400);
    
    // Store message
    db::store_message(
        &pool,
        &message_id,
        &recipient_hash,
        &req.encrypted_content,
        expiry,
    ).await?;
    
    info!("Message stored successfully with ID: {}", hex::encode(&message_id));
    
    // Return success response
    Ok(HttpResponse::Created().json(SendMessageResponse {
        message_id: hex::encode(&message_id),
        status: "sent".to_string(),
    }))
}

// Get pending messages
#[get("/messages/{connection_token}")]
pub async fn get_messages(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ServerError> {
    let token = path.into_inner();
    info!("Received message fetch request with token: {}", token);
    
    // Verify token
    let public_key_hash = db::verify_connection_token(&pool, &token).await?;
    
    // Get pending messages
    let messages = db::get_pending_messages(&pool, &public_key_hash).await?;
    
    info!("Found {} pending messages", messages.len());
    
    // Return messages
    Ok(HttpResponse::Ok().json(FetchMessagesResponse {
        messages,
        more_available: false, // Simplified for now
    }))
}

// Delete (acknowledge) a message
#[delete("/messages/{message_id}")]
pub async fn delete_message(
    pool: web::Data<PgPool>,
    auth: web::Header<String>,
    path: web::Path<String>,
) -> Result<HttpResponse, ServerError> {
    let message_id_hex = path.into_inner();
    info!("Received message delete request for ID: {}", message_id_hex);
    
    // Extract token from Authorization header
    let token = auth.trim_start_matches("Bearer ").trim();
    
    // Verify token
    db::verify_connection_token(&pool, token).await?;
    
    // Convert hex to bytes
    let message_id = match hex::decode(&message_id_hex) {
        Ok(id) => id,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid message ID format".to_string(),
            });
        }
    };
    
    // Mark message as delivered
    let success = db::mark_message_delivered(&pool, &message_id).await?;
    
    if success {
        info!("Message marked as delivered: {}", message_id_hex);
        Ok(HttpResponse::NoContent().finish())
    } else {
        info!("Message not found: {}", message_id_hex);
        Err(ServerError::NotFoundError {
            resource: format!("Message {}", message_id_hex),
        })
    }
}