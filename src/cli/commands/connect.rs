// client/src/cli/commands/connect.rs
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

use crate::crypto::keys::KeyManager;
use crate::network::connection::ServerConnection;
use crate::storage::config::Config;

pub async fn execute(matches: &ArgMatches, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Executing connect command");
    
    // Extract command arguments
    let server_url = matches.value_of("server").unwrap_or(&config.server_url);
    let background = matches.is_present("background");
    let timeout = matches.value_of("timeout")
        .map(|s| s.parse::<u64>().unwrap_or(30))
        .unwrap_or(30);
    let refresh_token = matches.is_present("refresh-token");
    
    debug!("Connect options - Server URL: {}, Background: {}, Timeout: {}s, Refresh token: {}",
           server_url, background, timeout, refresh_token);
    
    // Update config if server URL changed
    let mut updated_config = config.clone();
    if server_url != config.server_url {
        info!("Updating server URL to: {}", server_url);
        updated_config.update_server_url(server_url);
    }
    
    // Ensure storage directories exist
    updated_config.ensure_directories_exist()?;
    
    // Initialize key manager
    let keys_path = updated_config.get_keys_path().to_string_lossy().to_string();
    let key_manager = KeyManager::new(&keys_path)?;
    
    // Check if we have our own identity
    let identity = match key_manager.get_identity() {
        Some(identity) => identity.clone(),
        None => {
            println!("No identity keys found. Run 'secnet keygen' first.");
            error!("No identity keys found for connect command");
            return Err("No identity keys found".into());
        }
    };
    
    // Initialize server connection
    let mut server_connection = ServerConnection::new(updated_config.clone(), Some(identity.clone()))?;
    
    // Check existing connection token
    if refresh_token || updated_config.connection_token.is_none() {
        println!("Announcing public keys to server...");
        info!("Announcing public keys to server to get a connection token");
        
        match server_connection.announce().await {
            Ok(token) => {
                println!("Successfully connected to server");
                println!("Received connection token: {}", token);
                info!("Successfully received connection token");
                
                // Update connection token in config
                updated_config.update_connection_token(&token);
            },
            Err(e) => {
                println!("Failed to connect to server: {:?}", e);
                error!("Failed to connect to server: {:?}", e);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    format!("Failed to connect to server: {:?}", e)
                )));
            }
        }
    } else {
        println!("Using existing connection token");
        debug!("Using existing connection token: {:?}", updated_config.connection_token);
    }
    
    // Save updated config
    let config_path = Path::new(&updated_config.storage_path).join("config.json");
    if let Err(e) = updated_config.save(&config_path) {
        error!("Failed to save updated config: {}", e);
        return Err(Box::new(e));
    }
    
    // Check server connection
    println!("Testing connection to server...");
    info!("Testing connection to server");
    
    match server_connection.check_server_connection().await {
        Ok(true) => {
            println!("Server connection is active");
            info!("Server connection is active");
        },
        Ok(false) => {
            println!("Server connection check failed");
            warn!("Server connection check failed");
            return Err("Server connection check failed".into());
        },
        Err(e) => {
            println!("Failed to check server connection: {:?}", e);
            error!("Failed to check server connection: {:?}", e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to check server connection: {:?}", e)
            )));
        }
    }
    
    // Upload prekeys if needed
    println!("Checking if prekeys need to be uploaded...");
    info!("Checking prekey status");
    
    let prekeys = key_manager.get_prekeys();
    if prekeys.is_empty() {
        println!("No prekeys available. Generate new identity keys with 'secnet keygen'");
        warn!("No prekeys available for upload");
    } else {
        println!("Uploading {} prekeys to server...", prekeys.len());
        info!("Uploading {} prekeys to server", prekeys.len());
        
        match server_connection.upload_prekeys(prekeys).await {
            Ok(count) => {
                println!("{} prekeys uploaded successfully", count);
                info!("{} prekeys uploaded successfully", count);
            },
            Err(e) => {
                println!("Failed to upload prekeys: {:?}", e);
                error!("Failed to upload prekeys: {:?}", e);
                // Continue anyway
            }
        }
    }
    
    // Run in background mode if requested
    if background {
        println!("Starting background connection mode");
        println!("Messages will be fetched every {} seconds", updated_config.message_fetch_interval);
        info!("Starting background connection mode");
        
        match server_connection.fetch_messages_background(updated_config.message_fetch_interval).await {
            Ok(()) => {
                println!("Background connection started successfully");
                println!("Press Ctrl+C to stop");
                info!("Background connection started successfully");
                
                // Keep running until interrupted
                loop {
                    sleep(Duration::from_secs(1)).await;
                    
                    // Check for Ctrl+C
                    if tokio::signal::ctrl_c().await.is_ok() {
                        println!("\nReceived interrupt signal, stopping background connection");
                        info!("Received interrupt signal, stopping background connection");
                        break;
                    }
                }
            },
            Err(e) => {
                println!("Failed to start background connection: {:?}", e);
                error!("Failed to start background connection: {:?}", e);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    format!("Failed to start background connection: {:?}", e)
                )));
            }
        }
    } else {
        println!("Connection to server verified successfully");
        info!("Connection to server verified successfully");
    }
    
    Ok(())
}