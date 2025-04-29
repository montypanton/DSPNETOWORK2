// client/src/cli/commands/msg.rs
use clap::ArgMatches;
use log::{debug, error, info, trace, warn};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use prettytable::{Table, Row, Cell};
use chrono::{DateTime, Local};
use uuid::Uuid;
use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyManager;
use crate::network::connection::{Message, ServerConnection};
use crate::storage::config::Config;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredMessage {
    id: String,
    sender_fingerprint: String,
    content: Vec<u8>,
    timestamp: u64,
    read: bool,
}

pub async fn execute(matches: &ArgMatches, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Executing message command");
    
    // Ensure storage directories exist
    config.ensure_directories_exist()?;
    
    // Initialize key manager
    let keys_path = config.get_keys_path().to_string_lossy().to_string();
    let mut key_manager = KeyManager::new(&keys_path)?;
    
    // Check if we have our own identity
    let identity = match key_manager.get_identity() {
        Some(identity) => identity.clone(),
        None => {
            println!("No identity keys found. Run 'secnet keygen' first.");
            error!("No identity keys found for message command");
            return Err("No identity keys found".into());
        }
    };
    
    // Initialize server connection
    let mut server_connection = ServerConnection::new(config.clone(), Some(identity))?;
    
    match matches.subcommand() {
        ("send", Some(sub_m)) => {
            send_message(sub_m, &mut key_manager, &server_connection, config).await?;
        },
        ("fetch", Some(_)) => {
            fetch_messages(&mut key_manager, &server_connection, config).await?;
        },
        ("read", Some(sub_m)) => {
            read_messages(sub_m, &mut key_manager, config).await?;
        },
        ("chat", Some(sub_m)) => {
            interactive_chat(sub_m, &mut key_manager, &server_connection, config).await?;
        },
        _ => {
            println!("Unknown message subcommand. Use --help for usage information.");
            info!("Unknown message subcommand specified");
        }
    }
    
    info!("Message command completed successfully");
    Ok(())
}

async fn send_message(
    matches: &ArgMatches,
    key_manager: &mut KeyManager,
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint = matches.value_of("FINGERPRINT").unwrap();
    let message_content = matches.value_of("MESSAGE").unwrap();
    let topic = matches.value_of("topic");
    let file_path = matches.value_of("file");
    
    info!("Sending message to recipient: {}", fingerprint);
    if let Some(topic) = topic {
        info!("Message will be sent to topic: {}", topic);
    }
    
    debug!("Message send options - Fingerprint: {}, Topic: {:?}, File: {:?}",
           fingerprint, topic, file_path);
    
    // Check if peer exists
    if topic.is_none() && key_manager.get_peer(fingerprint).is_none() {
        println!("No peer found with fingerprint: {}", fingerprint);
        error!("No peer found with fingerprint: {}", fingerprint);
        return Err("Peer not found".into());
    }
    
    // Prepare message content
    let content = if let Some(path) = file_path {
        println!("Reading message content from file: {}", path);
        info!("Reading message content from file: {}", path);
        
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        debug!("Read {} bytes from file", data.len());
        data
    } else {
        message_content.as_bytes().to_vec()
    };
    
    // Send message
    if let Some(topic_hash) = topic {
        println!("Sending message to topic: {}", topic_hash);
        
        // For topic messages, we need to encrypt for each subscriber
        // In a real implementation, this would be more complex
        // For simulation, we'll just encrypt with a default key
        
        // Create a simple JSON structure for the topic message
        #[derive(Serialize)]
        struct TopicMessage {
            text: String,
            sender: String,
            timestamp: u64,
        }
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let topic_msg = TopicMessage {
            text: String::from_utf8_lossy(&content).to_string(),
            sender: key_manager.get_identity().unwrap().fingerprint.clone(),
            timestamp: current_time,
        };
        
        let serialized = serde_json::to_vec(&topic_msg)?;
        
        // In a real implementation, this would be properly encrypted for the topic
        // For simulation, we'll just send the serialized data
        match server_connection.publish_to_topic(topic_hash, &serialized, None).await {
            Ok(id) => {
                println!("Message sent to topic successfully with ID: {}", id);
                info!("Message sent to topic: {}, ID: {}", topic_hash, id);
                Ok(())
            },
            Err(e) => {
                println!("Failed to send message to topic: {:?}", e);
                error!("Failed to send message to topic: {:?}", e);
                Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to send message: {:?}", e))))
            }
        }
    } else {
        println!("Encrypting message for peer: {}", fingerprint);
        info!("Encrypting message for peer: {}, {} bytes", fingerprint, content.len());
        
        // Encrypt message
        let encrypted = match key_manager.encrypt_message(fingerprint, &content) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to encrypt message: {:?}", e);
                error!("Failed to encrypt message: {:?}", e);
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to encrypt message: {:?}", e))));
            }
        };
        
        debug!("Message encrypted successfully, {} bytes", encrypted.len());
        
        // Get peer's public key hash (using fingerprint for now)
        let peer_key_hash = fingerprint;
        
        // Send encrypted message to server
        match server_connection.send_message(peer_key_hash, &encrypted, None).await {
            Ok(id) => {
                println!("Message sent successfully with ID: {}", id);
                info!("Message sent successfully to: {}, ID: {}", fingerprint, id);
                Ok(())
            },
            Err(e) => {
                println!("Failed to send message: {:?}", e);
                error!("Failed to send message: {:?}", e);
                Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to send message: {:?}", e))))
            }
        }
    }
}

async fn fetch_messages(
    key_manager: &mut KeyManager,
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Fetching pending messages from server");
    println!("Fetching pending messages from server...");
    
    // Fetch messages
    let messages = match server_connection.fetch_messages().await {
        Ok(msgs) => msgs,
        Err(e) => {
            println!("Failed to fetch messages: {:?}", e);
            error!("Failed to fetch messages: {:?}", e);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to fetch messages: {:?}", e))));
        }
    };
    
    if messages.is_empty() {
        println!("No pending messages.");
        info!("No pending messages found");
        return Ok(());
    }
    
    println!("Received {} pending messages", messages.len());
    info!("Received {} pending messages", messages.len());
    
    // Process and store messages
    let mut processed_count = 0;
    let mut failed_count = 0;
    
    for message in messages {
        debug!("Processing message: {}", message.id);
        
        // In a real implementation, we would identify the sender from the message
        // For simulation, we'll assume the recipient_key_hash is actually the sender's fingerprint
        let sender_fingerprint = message.recipient_key_hash.clone();
        
        // Check if we know this peer
        if key_manager.get_peer(&sender_fingerprint).is_none() {
            warn!("Received message from unknown peer: {}", sender_fingerprint);
            println!("Warning: Received message from unknown peer: {}", sender_fingerprint);
            failed_count += 1;
            continue;
        }
        
        // Decrypt message
        let decrypted = match key_manager.decrypt_message(&sender_fingerprint, &message.encrypted_content) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to decrypt message: {:?}", e);
                println!("Warning: Failed to decrypt message: {:?}", e);
                failed_count += 1;
                continue;
            }
        };
        
        debug!("Message decrypted successfully, {} bytes", decrypted.len());
        
        // Store message
        store_message(
            config, 
            &StoredMessage {
                id: message.id.clone(),
                sender_fingerprint: sender_fingerprint.clone(),
                content: decrypted,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                read: false,
            }
        )?;
        
        // Acknowledge message receipt
        match server_connection.acknowledge_message(&message.id).await {
            Ok(()) => {
                debug!("Message acknowledged: {}", message.id);
            },
            Err(e) => {
                warn!("Failed to acknowledge message: {}, error: {:?}", message.id, e);
            }
        }
        
        processed_count += 1;
    }
    
    println!("Processed {} messages, {} failed", processed_count, failed_count);
    info!("Processed {} messages, {} failed", processed_count, failed_count);
    
    Ok(())
}

async fn read_messages(
    matches: &ArgMatches,
    key_manager: &mut KeyManager,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Reading messages");
    
    // Load stored messages
    let messages = load_messages(config)?;
    
    if messages.is_empty() {
        println!("No stored messages.");
        info!("No stored messages found");
        return Ok(());
    }
    
    // Check if a specific ID was requested
    if let Some(id) = matches.value_of("ID") {
        info!("Reading specific message with ID: {}", id);
        
        // Find the requested message
        let message = messages.iter().find(|m| m.id == id);
        
        match message {
            Some(msg) => {
                display_message(msg, key_manager)?;
                mark_message_as_read(config, id)?;
            },
            None => {
                println!("No message found with ID: {}", id);
                error!("No message found with ID: {}", id);
                return Err("Message not found".into());
            }
        }
    } else {
        // Display all unread messages
        let unread = messages.iter().filter(|m| !m.read).collect::<Vec<_>>();
        
        if unread.is_empty() {
            println!("No unread messages.");
            info!("No unread messages found");
        } else {
            println!("You have {} unread messages:", unread.len());
            info!("Displaying {} unread messages", unread.len());
            
            for msg in unread {
                display_message(msg, key_manager)?;
                mark_message_as_read(config, &msg.id)?;
            }
        }
    }
    
    Ok(())
}

async fn interactive_chat(
    matches: &ArgMatches,
    key_manager: &mut KeyManager,
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint = matches.value_of("FINGERPRINT").unwrap();
    info!("Starting interactive chat with peer: {}", fingerprint);
    
    // Check if peer exists
    let peer = match key_manager.get_peer(fingerprint) {
        Some(peer) => peer.clone(),
        None => {
            println!("No peer found with fingerprint: {}", fingerprint);
            error!("No peer found with fingerprint: {}", fingerprint);
            return Err("Peer not found".into());
        }
    };
    
    let peer_name = peer.alias.as_deref().unwrap_or(fingerprint);
    println!("\nStarting chat with {}", peer_name);
    println!("Type .exit to end the conversation\n");
    
    // Start message fetching task
    let fetch_interval = config.message_fetch_interval;
    let server_conn_clone = server_connection.clone();
    let key_manager_clone = key_manager.clone();
    let config_clone = config.clone();
    let fingerprint_clone = fingerprint.to_string();
    
    let (tx, mut rx) = tokio::sync::mpsc::channel::<StoredMessage>(100);
    
    let fetch_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(fetch_interval));
        
        loop {
            interval.tick().await;
            debug!("Fetching messages in background");
            
            match server_conn_clone.fetch_messages().await {
                Ok(messages) => {
                    for message in messages {
                        // For simplicity, assume recipient_key_hash is the sender's fingerprint
                        let sender_fingerprint = message.recipient_key_hash.clone();
                        
                        // Only process messages from the chat partner
                        if sender_fingerprint != fingerprint_clone {
                            continue;
                        }
                        
                        // Decrypt message
                        match key_manager_clone.decrypt_message(&sender_fingerprint, &message.encrypted_content) {
                            Ok(decrypted) => {
                                let stored_msg = StoredMessage {
                                    id: message.id.clone(),
                                    sender_fingerprint: sender_fingerprint.clone(),
                                    content: decrypted,
                                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                    read: true,
                                };
                                
                                // Store message
                                if let Err(e) = store_message(&config_clone, &stored_msg) {
                                    error!("Failed to store message: {:?}", e);
                                    continue;
                                }
                                
                                // Send to display channel
                                let _ = tx.send(stored_msg).await;
                                
                                // Acknowledge message
                                let _ = server_conn_clone.acknowledge_message(&message.id).await;
                            },
                            Err(e) => {
                                error!("Failed to decrypt message: {:?}", e);
                            }
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to fetch messages: {:?}", e);
                    // Short sleep after error
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
    
    // Start chat loop
    let mut input = String::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut last_fetch = Instant::now();
    
    loop {
        // Check for incoming messages
        if rx.try_recv().is_ok() {
            // Refresh the screen when new messages arrive
            println!("\r{}: {}", peer_name, String::from_utf8_lossy(&rx.recv().await.unwrap().content));
            print!("> ");
            stdout.flush()?;
        }
        
        // Check if we need to prompt for input
        if last_fetch.elapsed() > Duration::from_millis(100) {
            // Check for user input with timeout
            print!("> ");
            stdout.flush()?;
            
            // Set up the input reading with a small timeout
            let mut input_available = false;
            let input_task = tokio::task::spawn_blocking(move || {
                let mut temp_input = String::new();
                match stdin.read_line(&mut temp_input) {
                    Ok(_) => Some(temp_input),
                    Err(_) => None,
                }
            });
            
            let timeout_future = sleep(Duration::from_millis(500));
            let input_result = tokio::select! {
                result = input_task => {
                    input_available = true;
                    result.unwrap_or(None)
                },
                _ = timeout_future => None,
            };
            
            if !input_available {
                // No input available, continue checking for messages
                last_fetch = Instant::now();
                continue;
            }
            
            if let Some(user_input) = input_result {
                input = user_input;
                let trimmed = input.trim();
                
                if trimmed == ".exit" {
                    println!("Exiting chat.");
                    break;
                }
                
                if !trimmed.is_empty() {
                    // Send message
                    let encrypted = match key_manager.encrypt_message(fingerprint, trimmed.as_bytes()) {
                        Ok(data) => data,
                        Err(e) => {
                            println!("Failed to encrypt message: {:?}", e);
                            error!("Failed to encrypt message: {:?}", e);
                            continue;
                        }
                    };
                    
                    match server_connection.send_message(fingerprint, &encrypted, None).await {
                        Ok(id) => {
                            debug!("Message sent successfully, ID: {}", id);
                        },
                        Err(e) => {
                            println!("Failed to send message: {:?}", e);
                            error!("Failed to send message: {:?}", e);
                        }
                    }
                }
            }
            
            last_fetch = Instant::now();
        }
        
        // Small sleep to avoid CPU spinning
        sleep(Duration::from_millis(10)).await;
    }
    
    // Clean up
    fetch_task.abort();
    
    info!("Interactive chat completed");
    Ok(())
}

// Helper functions for message storage

fn store_message(config: &Config, message: &StoredMessage) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Storing message ID: {}", message.id);
    
    let messages_dir = config.get_messages_path();
    if !messages_dir.exists() {
        fs::create_dir_all(&messages_dir)?;
    }
    
    let message_path = messages_dir.join(format!("{}.json", message.id));
    let serialized = serde_json::to_string_pretty(message)?;
    
    let mut file = File::create(message_path)?;
    file.write_all(serialized.as_bytes())?;
    
    debug!("Message stored successfully");
    Ok(())
}

fn load_messages(config: &Config) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
    debug!("Loading stored messages");
    
    let messages_dir = config.get_messages_path();
    if !messages_dir.exists() {
        debug!("Messages directory doesn't exist");
        return Ok(Vec::new());
    }
    
    let mut messages = Vec::new();
    
    for entry in std::fs::read_dir(messages_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            debug!("Loading message from: {:?}", path);
            
            let mut file = File::open(&path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            
            match serde_json::from_str::<StoredMessage>(&content) {
                Ok(message) => {
                    messages.push(message);
                },
                Err(e) => {
                    warn!("Failed to parse message file: {:?}, error: {:?}", path, e);
                }
            }
        }
    }
    
    // Sort by timestamp (newest first)
    messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    
    debug!("Loaded {} messages", messages.len());
    Ok(messages)
}

fn mark_message_as_read(config: &Config, message_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Marking message as read: {}", message_id);
    
    let messages_dir = config.get_messages_path();
    let message_path = messages_dir.join(format!("{}.json", message_id));
    
    if !message_path.exists() {
        warn!("Message file not found: {:?}", message_path);
        return Err("Message not found".into());
    }
    
    // Load the message
    let mut file = File::open(&message_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    
    let mut message: StoredMessage = serde_json::from_str(&content)?;
    
    // Update the read status
    message.read = true;
    
    // Save the updated message
    let serialized = serde_json::to_string_pretty(&message)?;
    let mut file = File::create(message_path)?;
    file.write_all(serialized.as_bytes())?;
    
    debug!("Message marked as read successfully");
    Ok(())
}

fn display_message(message: &StoredMessage, key_manager: &KeyManager) -> Result<(), Box<dyn std::error::Error>> {
    // Get peer information
    let sender_name = match key_manager.get_peer(&message.sender_fingerprint) {
        Some(peer) => peer.alias.as_deref().unwrap_or(&message.sender_fingerprint),
        None => &message.sender_fingerprint,
    };
    
    // Format timestamp
    let datetime: DateTime<Local> = DateTime::from_timestamp(message.timestamp as i64, 0)
        .map(|dt| dt.into())
        .unwrap_or_else(|| Local::now());
    
    // Display message
    println!("\n----- Message {} -----", message.id);
    println!("From: {}", sender_name);
    println!("Time: {}", datetime.format("%Y-%m-%d %H:%M:%S"));
    println!("Content: {}", String::from_utf8_lossy(&message.content));
    println!("-----------------------\n");
    
    Ok(())
}