// client/src/cli/commands/status.rs
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::fs;
use std::path::Path;
use chrono::{DateTime, Local};
use prettytable::prettytable;

use crate::crypto::keys::KeyManager;
use crate::network::connection::ServerConnection;
use crate::storage::config::Config;

pub async fn execute(matches: &ArgMatches, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Executing status command");
    
    // Check what status info was requested
    let show_keys = matches.is_present("keys");
    let show_connection = matches.is_present("connection");
    let show_messages = matches.is_present("messages");
    let show_entropy = matches.is_present("entropy");
    
    // If none specified, show everything
    let show_all = !show_keys && !show_connection && !show_messages && !show_entropy;
    
    debug!("Status options - Keys: {}, Connection: {}, Messages: {}, Entropy: {}, All: {}",
           show_keys, show_connection, show_messages, show_entropy, show_all);
    
    // Initialize key manager
    let keys_path = config.get_keys_path().to_string_lossy().to_string();
    let key_manager = KeyManager::new(&keys_path)?;
    
    // Get identity if available
    let identity = key_manager.get_identity();
    
    // Initialize server connection if needed
    let server_connection = if show_connection || show_all {
        if let Some(id) = identity {
            Some(ServerConnection::new(config.clone(), Some(id.clone()))?)
        } else {
            None
        }
    } else {
        None
    };
    
    println!("Secure Network Status Report");
    println!("============================\n");
    
    // Display client version
    println!("Client version: 0.1.0");
    println!("Secure Network Protocol Implementation\n");
    
    // Show key status
    if show_keys || show_all {
        show_key_status(&key_manager)?;
    }
    
    // Show connection status
    if show_connection || show_all {
        show_connection_status(&server_connection, config).await?;
    }
    
    // Show message stats
    if show_messages || show_all {
        show_message_stats(config)?;
    }
    
    // Show entropy status
    if show_entropy || show_all {
        show_entropy_status()?;
    }
    
    info!("Status command completed successfully");
    Ok(())
}

fn show_key_status(key_manager: &KeyManager) -> Result<(), Box<dyn std::error::Error>> {
    info!("Showing key status");
    
    println!("Key Status");
    println!("----------");
    
    // Check identity keys
    match key_manager.get_identity() {
        Some(identity) => {
            println!("Identity keys: Available");
            println!("  Fingerprint: {}", identity.fingerprint);
            if let Some(alias) = &identity.alias {
                println!("  Alias: {}", alias);
            }
            println!("  Key types: Ed25519, X25519, Kyber (Post-Quantum)");
            
            // Count peers
            let peers = key_manager.get_peers();
            println!("  Known peers: {}", peers.len());
            
            // Count prekeys
            let prekeys = key_manager.get_prekeys();
            println!("  Available prekeys: {}", prekeys.len());
            
            debug!("Identity key status displayed");
        },
        None => {
            println!("Identity keys: Not found");
            println!("Run 'secnet keygen' to generate identity keys");
            warn!("No identity keys found");
        }
    }
    
    println!();
    Ok(())
}

async fn show_connection_status(
    server_connection: &Option<ServerConnection>,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Showing connection status");
    
    println!("Connection Status");
    println!("-----------------");
    
    // Show server URL
    println!("Server URL: {}", config.server_url);
    
    // Check connection token
    match &config.connection_token {
        Some(token) => {
            println!("Connection token: Available");
            debug!("Connection token: {}", token);
            
            // Test connection if possible
            if let Some(conn) = server_connection {
                println!("Testing server connection...");
                
                match conn.check_server_connection().await {
                    Ok(true) => {
                        println!("Server connection: Active");
                        info!("Server connection is active");
                    },
                    Ok(false) => {
                        println!("Server connection: Inactive");
                        warn!("Server connection is inactive");
                    },
                    Err(e) => {
                        println!("Server connection: Error - {:?}", e);
                        error!("Server connection error: {:?}", e);
                    }
                }
            }
        },
        None => {
            println!("Connection token: Not available");
            println!("Run 'secnet connect' to establish connection");
            warn!("No connection token available");
        }
    }
    
    // Show last sync time
    if let Some(last_sync) = config.last_server_sync {
        let datetime: DateTime<Local> = DateTime::from_timestamp(last_sync as i64, 0)
            .map(|dt| dt.into())
            .unwrap_or_else(|| Local::now());
        
        println!("Last server sync: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
    } else {
        println!("Last server sync: Never");
    }
    
    println!("Auto-fetch messages: {}", if config.auto_fetch_messages { "Enabled" } else { "Disabled" });
    println!("Fetch interval: {} seconds", config.message_fetch_interval);
    
    println!();
    Ok(())
}

fn show_message_stats(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Showing message statistics");
    
    println!("Message Statistics");
    println!("------------------");
    
    let messages_dir = config.get_messages_path();
    if !messages_dir.exists() {
        println!("Messages directory: Not found");
        println!("No messages have been received yet");
        debug!("Messages directory not found");
        println!();
        return Ok(());
    }
    
    // Count message files
    let mut total_count = 0;
    let mut read_count = 0;
    let mut unread_count = 0;
    let mut peers = Vec::new();
    
    for entry in fs::read_dir(&messages_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            total_count += 1;
            
            // Try to parse the file to get more stats
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(message) = serde_json::from_str::<serde_json::Value>(&content) {
                    // Count read/unread
                    if let Some(read) = message.get("read").and_then(|v| v.as_bool()) {
                        if read {
                            read_count += 1;
                        } else {
                            unread_count += 1;
                        }
                    }
                    
                    // Track unique peers
                    if let Some(sender) = message.get("sender_fingerprint").and_then(|v| v.as_str()) {
                        if !peers.contains(&sender.to_string()) {
                            peers.push(sender.to_string());
                        }
                    }
                }
            }
        }
    }
    
    println!("Total messages: {}", total_count);
    println!("  Read: {}", read_count);
    println!("  Unread: {}", unread_count);
    println!("Unique senders: {}", peers.len());
    
    // Show topic stats
    let topics_dir = config.get_topics_path();
    if topics_dir.exists() {
        let mut topic_count = 0;
        let mut subscribed_count = 0;
        
        for entry in fs::read_dir(&topics_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                topic_count += 1;
                
                // Try to parse the file to get more stats
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(topic) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(subscribed) = topic.get("subscribed").and_then(|v| v.as_bool()) {
                            if subscribed {
                                subscribed_count += 1;
                            }
                        }
                    }
                }
            }
        }
        
        println!("Topics: {}", topic_count);
        println!("  Subscribed: {}", subscribed_count);
    } else {
        println!("Topics: 0");
    }
    
    println!();
    Ok(())
}

fn show_entropy_status() -> Result<(), Box<dyn std::error::Error>> {
    info!("Showing entropy status");
    
    println!("Entropy Status");
    println!("--------------");
    
    // In a real implementation, we would check system entropy sources
    // For this simulation, we'll just provide some basic information
    
    #[cfg(target_family = "unix")]
    {
        // On Unix-like systems, check if /dev/random and /dev/urandom exist
        let random_exists = Path::new("/dev/random").exists();
        let urandom_exists = Path::new("/dev/urandom").exists();
        
        println!("/dev/random available: {}", if random_exists { "Yes" } else { "No" });
        println!("/dev/urandom available: {}", if urandom_exists { "Yes" } else { "No" });
        
        // Try to read entropy estimate
        if let Ok(content) = fs::read_to_string("/proc/sys/kernel/random/entropy_avail") {
            if let Ok(entropy) = content.trim().parse::<u32>() {
                println!("Available entropy: {} bits", entropy);
                
                // Provide some interpretation
                if entropy < 200 {
                    println!("Entropy level: Low (may cause key generation to block)");
                } else if entropy < 1000 {
                    println!("Entropy level: Moderate");
                } else {
                    println!("Entropy level: Good");
                }
            }
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        // On Windows, we don't have easy access to entropy information
        println!("Using CryptoAPI/BCrypt for entropy");
        println!("Entropy assessment not available on Windows");
    }
    
    // Always provide this general information
    println!("Using: Cryptographically secure RNG (rand crate)");
    println!("Key generation: Uses hardware RNG when available");
    
    println!();
    Ok(())
}