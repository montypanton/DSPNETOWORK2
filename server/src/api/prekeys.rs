use actix_web::{get, post, web, HttpResponse};
use log::{debug, error, info};
use sqlx::PgPool;

use crate::db;
use crate::error::ServerError;
use crate::models::{PreKeysResponse, PreKeysUploadRequest};

// Upload prekeys
#[post("/prekeys")]
pub async fn upload_prekeys(
    pool: web::Data<PgPool>,
    auth: web::Header<String>,
    req: web::Json<PreKeysUploadRequest>,
) -> Result<HttpResponse, ServerError> {
    info!("Received prekey upload request");
    
    // Extract token from Authorization header
    let token = auth.trim_start_matches("Bearer ").trim();
    
    // Verify token
    let public_key_hash = db::verify_connection_token(&pool, token).await?;
    
    // Verify the public key hash matches
    let req_hash = match hex::decode(&req.public_key_hash) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid public key hash format".to_string(),
            });
        }
    };
    
    if req_hash != public_key_hash {
        return Err(ServerError::AuthenticationError);
    }
    
    // Store prekeys
    let count = db::store_prekeys(&pool, &public_key_hash, &req.prekeys).await?;
    
    info!("Stored {} prekeys successfully", count);
    
    // Return success response
    Ok(HttpResponse::Ok().json(PreKeysResponse {
        status: "success".to_string(),
        count,
    }))
}

// Get prekeys for a client
#[get("/prekeys/{public_key_hash}")]
pub async fn get_prekeys(
    pool: web::Data<PgPool>,
    auth: web::Header<String>,
    path: web::Path<String>,
) -> Result<HttpResponse, ServerError> {
    let public_key_hash_hex = path.into_inner();
    info!("Received prekey fetch request for: {}", public_key_hash_hex);
    
    // Extract token from Authorization header
    let token = auth.trim_start_matches("Bearer ").trim();
    
    // Verify token
    db::verify_connection_token(&pool, token).await?;
    
    // Convert hex to bytes
    let public_key_hash = match hex::decode(&public_key_hash_hex) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(ServerError::BadRequestError {
                message: "Invalid public key hash format".to_string(),
            });
        }
    };
    
    // Get prekeys
    let prekeys = db::get_prekeys(&pool, &public_key_hash, 3).await?;
    
    info!("Returning {} prekeys", prekeys.len());
    
    // Return prekeys
    Ok(HttpResponse::Ok().json(prekeys))
}