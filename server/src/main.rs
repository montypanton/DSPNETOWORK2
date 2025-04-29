// server/src/main.rs
use actix_web::{middleware, web, App, HttpServer};
use dotenv::dotenv;
use env_logger::Env;
use log::{info, warn};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::time::Duration;

mod api;
mod auth;
mod db;
mod error;
mod message;
mod models;
mod topic;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();
    
    // Initialize logger
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    
    info!("Starting Secure Network Protocol server");
    
    // Get configuration from environment
    let server_port = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("SERVER_PORT must be a valid port number");
    
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    info!("Connecting to database...");
    
    // Create database connection pool
    let db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("Failed to create database connection pool");
    
    info!("Database connection established");
    
    // Run migrations
    info!("Running database migrations...");
    match sqlx::migrate!("./migrations").run(&db_pool).await {
        Ok(_) => info!("Migrations completed successfully"),
        Err(e) => {
            warn!("Migration error: {:?}", e);
            info!("Continuing anyway, assuming schema is already set up");
        }
    }
    
    // Set up scheduled tasks
    let pool_clone = db_pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Every hour
        loop {
            interval.tick().await;
            info!("Running scheduled maintenance tasks");
            
            // Delete expired messages
            match sqlx::query("SELECT delete_expired_messages()")
                .execute(&pool_clone)
                .await
            {
                Ok(_) => info!("Expired messages deleted"),
                Err(e) => warn!("Failed to delete expired messages: {:?}", e),
            }
            
            // Clean up used prekeys
            match sqlx::query("SELECT cleanup_used_prekeys()")
                .execute(&pool_clone)
                .await
            {
                Ok(_) => info!("Used prekeys cleaned up"),
                Err(e) => warn!("Failed to clean up used prekeys: {:?}", e),
            }
        }
    });
    
    // Start HTTP server
    info!("Starting HTTP server on port {}", server_port);
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .service(
                web::scope("/api")
                    // Authentication endpoints
                    .service(api::auth::announce)
                    .service(api::auth::refresh_token)
                    .service(api::auth::ping)
                    
                    // Prekey endpoints
                    .service(api::prekeys::upload_prekeys)
                    .service(api::prekeys::get_prekeys)
                    
                    // Message endpoints
                    .service(api::messages::send_message)
                    .service(api::messages::get_messages)
                    .service(api::messages::delete_message)
                    
                    // Topic endpoints
                    .service(api::topics::create_topic)
                    .service(api::topics::list_topics)
                    .service(api::topics::subscribe_topic)
                    .service(api::topics::unsubscribe_topic)
                    .service(api::topics::publish_topic)
            )
    })
    .bind(("0.0.0.0", server_port))?
    .run()
    .await
}