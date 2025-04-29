use actix_web::{get, post, web, HttpResponse, Responder};
use log::{debug, error, info};
use sqlx::PgPool;
use uuid::Uuid;

use crate::db;
use crate::error::ServerError;
use crate::models::{AnnouncementRequest, AnnouncementResponse};

// Announce public keys and get connection token
#[post("/announce")]
pub async fn announce(
    pool: web::Data<PgPool>,
    req: web::Json<AnnouncementRequest>,
) -> Result<HttpResponse, ServerError> {
    info!("Received announcement request");
    
    // Calculate hash of public keys
    let public_key_hash = db::calculate_key_hash(
        &req.ed25519_public_key,
        &req.x25519_public_key,
        &req.kyber_public_key,
    );
    
    // Generate a unique connection token
    let connection_token = Uuid::new_v4().to_string();
    
    // Store the public keys and token in database
    db::store_public_keys(
        &pool,
        &public_key_hash,
        &req.ed25519_public_key,
        &req.x25519_public_key,
        &req.kyber_public_key,
        &connection_token,
    ).await?;
    
    info!("Public keys stored successfully for hash: {}", hex::encode(&public_key_hash));
    
    // Return the connection token and public key hash
    Ok(HttpResponse::Ok().json(AnnouncementResponse {
        connection_token,
        public_key_hash: hex::encode(&public_key_hash),
    }))
}

// Refresh connection token
#[post("/connection/refresh")]
pub async fn refresh_token(
    pool: web::Data<PgPool>,
    auth: web::Header<String>,
) -> Result<HttpResponse, ServerError> {
    info!("Received token refresh request");
    
    // Extract token from Authorization header
    let token = auth.trim_start_matches("Bearer ").trim();
    
    // Verify existing token
    let public_key_hash = db::verify_connection_token(&pool, token).await?;
    
    // Generate new token
    let new_token = Uuid::new_v4().to_string();
    
    // Update token in database - simplified for brevity
    let token_uuid = Uuid::parse_str(&new_token).unwrap();
    sqlx::query!(
        "UPDATE public_keys SET connection_token = $1 WHERE public_key_hash = $2",
        token_uuid,
        public_key_hash
    )
    .execute(&pool)
    .await?;
    
    info!("Token refreshed successfully");
    
    // Return new token
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "connection_token": new_token,
        "status": "refreshed"
    })))
}

// Simple ping endpoint to check server status
#[get("/connection/ping")]
pub async fn ping() -> impl Responder {
    HttpResponse::Ok().body("Pong")
}