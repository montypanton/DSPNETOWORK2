// client/src/cli/commands/topic.rs
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::fs::{self, File};
use std::io::{Read, Write};
use prettytable::{Table, Row, Cell};
use serde::{Deserialize, Serialize};

use crate::crypto::keys::KeyManager;
use crate::network::connection::ServerConnection;
use crate::storage::config::Config;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredTopic {
    hash: String,
    name: Option<String>,  // Local name, not shared with server
    subscribed: bool,
    created_at: u64,
    blinded: bool,
}

pub async fn execute(matches: &ArgMatches, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Executing topic command");
    
    // Ensure storage directories exist
    config.ensure_directories_exist()?;
    
    // Initialize key manager
    let keys_path = config.get_keys_path().to_string_lossy().to_string();
    let key_manager = KeyManager::new(&keys_path)?;
    
    // Check if we have our own identity
    let identity = match key_manager.get_identity() {
        Some(identity) => identity.clone(),
        None => {
            println!("No identity keys found. Run 'secnet keygen' first.");
            error!("No identity keys found for topic command");
            return Err("No identity keys found".into());
        }
    };
    
    // Initialize server connection
    let server_connection = ServerConnection::new(config.clone(), Some(identity))?;
    
    match matches.subcommand() {
        Some(("create", sub_m)) => {
            create_topic(sub_m, &server_connection, config).await?;
        },
        Some(("list", _)) => {
            list_topics(&server_connection, config).await?;
        },
        Some(("subscribe", sub_m)) => {
            subscribe_topic(sub_m, &server_connection, config).await?;
        },
        Some(("unsubscribe", sub_m)) => {
            unsubscribe_topic(sub_m, &server_connection, config).await?;
        },
        Some(("publish", sub_m)) => {
            publish_topic(sub_m, &server_connection, config).await?;
        },
        _ => {
            println!("Unknown topic subcommand. Use --help for usage information.");
            info!("Unknown topic subcommand specified");
        }
    }
    
    info!("Topic command completed successfully");
    Ok(())
}

async fn create_topic(
    _matches: &ArgMatches,
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Creating new topic");
    println!("Creating new topic...");
    
    // Prompt for local topic name
    println!("Enter a local name for this topic (optional, never shared with server): ");
    let mut name = String::new();
    std::io::stdin().read_line(&mut name)?;
    let name = if name.trim().is_empty() { None } else { Some(name.trim().to_string()) };
    
    if let Some(n) = &name {
        debug!("Using local topic name: {}", n);
    }
    
    // Create topic on server
    match server_connection.create_topic().await {
        Ok(topic_hash) => {
            println!("Topic created successfully with hash: {}", topic_hash);
            info!("Topic created successfully: {}", topic_hash);
            
            // Store topic locally
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let topic = StoredTopic {
                hash: topic_hash.clone(),
                name,
                subscribed: true,  // Auto-subscribe when creating
                created_at: timestamp,
                blinded: false,
            };
            
            store_topic(config, &topic)?;
            
            // Auto-subscribe
            println!("Auto-subscribing to newly created topic");
            info!("Auto-subscribing to newly created topic");
            
            match server_connection.subscribe_to_topic(&topic_hash, false).await {
                Ok(()) => {
                    println!("Subscribed to topic successfully");
                    info!("Subscribed to topic successfully");
                },
                Err(e) => {
                    println!("Warning: Failed to subscribe to topic: {:?}", e);
                    warn!("Failed to subscribe to topic: {:?}", e);
                    // Continue anyway since topic was created
                }
            }
            
            Ok(())
        },
        Err(e) => {
            println!("Failed to create topic: {:?}", e);
            error!("Failed to create topic: {:?}", e);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to create topic: {:?}", e)
            )))
        }
    }
}

async fn list_topics(
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Listing topics");
    println!("Listing topics...");
    
    // Load locally stored topics
    let local_topics = load_topics(config)?;
    
    // Fetch topics from server
    let server_topics = match server_connection.list_topics().await {
        Ok(topics) => {
            info!("Fetched {} topics from server", topics.len());
            topics
        },
        Err(e) => {
            println!("Warning: Failed to fetch topics from server: {:?}", e);
            warn!("Failed to fetch topics from server: {:?}", e);
            Vec::new()
        }
    };
    
    // Merge local and server topics
    let mut all_topics = Vec::new();
    
    // Add all local topics
    for local in &local_topics {
        all_topics.push(local.clone());
    }
    
    // Add server topics that aren't in local storage
    for server in &server_topics {
        if !local_topics.iter().any(|t| t.hash == server.hash) {
            let new_topic = StoredTopic {
                hash: server.hash.clone(),
                name: None,
                subscribed: false,
                created_at: server.created_at,
                blinded: false,
            };
            all_topics.push(new_topic);
        }
    }
    
    // Display topics
    if all_topics.is_empty() {
        println!("No topics found.");
        return Ok(());
    }
    
    println!("Found {} topics:", all_topics.len());
    
    // Create a table for pretty output
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Hash"),
        Cell::new("Name"),
        Cell::new("Subscribed"),
        Cell::new("Created"),
    ]));
    
    for topic in all_topics {
        let name = topic.name.as_deref().unwrap_or("(unnamed)");
        let subscribed = if topic.subscribed { "Yes" } else { "No" };
        
        // Format timestamp
        let datetime = chrono::DateTime::<chrono::Local>::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(topic.created_at)
        );
        let created = datetime.format("%Y-%m-%d %H:%M").to_string();
        
        table.add_row(Row::new(vec![
            Cell::new(&topic.hash),
            Cell::new(name),
            Cell::new(subscribed),
            Cell::new(&created),
        ]));
    }
    
    // Print the table
    table.printstd();
    
    Ok(())
}

async fn subscribe_topic(
    matches: &ArgMatches,
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_hash = matches.value_of("TOPIC_HASH").unwrap();
    info!("Subscribing to topic: {}", topic_hash);
    
    let blinded = matches.is_present("blinded");
    if blinded {
        println!("Using blinded subscription for privacy");
        info!("Using blinded subscription");
    }
    
    // Check if already subscribed
    let local_topics = load_topics(config)?;
    let existing = local_topics.iter().find(|t| t.hash == topic_hash);
    
    if let Some(topic) = existing {
        if topic.subscribed {
            println!("Already subscribed to topic: {}", topic_hash);
            info!("Already subscribed to topic: {}", topic_hash);
            return Ok(());
        }
    }
    
    // Subscribe on server
    println!("Subscribing to topic: {}", topic_hash);
    
    match server_connection.subscribe_to_topic(topic_hash, blinded).await {
        Ok(()) => {
            println!("Subscribed to topic successfully");
            info!("Subscribed to topic successfully");
            
            // Update local storage
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // Create new topic data
            let topic = if let Some(existing) = existing {
                // Update existing topic
                let mut updated = existing.clone();
                updated.subscribed = true;
                updated.blinded = blinded;
                updated
            } else {
                // Create new topic entry
                StoredTopic {
                    hash: topic_hash.to_string(),
                    name: None,
                    subscribed: true,
                    created_at: timestamp,
                    blinded,
                }
            };
            
            store_topic(config, &topic)?;
            
            // Optional: Prompt for local name if not set
            if topic.name.is_none() {
                println!("Would you like to set a local name for this topic? (y/N): ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                
                if input.trim().to_lowercase() == "y" {
                    println!("Enter local name for topic (never shared with server): ");
                    let mut name = String::new();
                    std::io::stdin().read_line(&mut name)?;
                    
                    if !name.trim().is_empty() {
                        let mut updated = topic.clone();
                        updated.name = Some(name.trim().to_string());
                        store_topic(config, &updated)?;
                        
                        println!("Local name set successfully");
                        info!("Local name set for topic: {}", topic_hash);
                    }
                }
            }
            
            Ok(())
        },
        Err(e) => {
            println!("Failed to subscribe to topic: {:?}", e);
            error!("Failed to subscribe to topic: {:?}", e);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to subscribe to topic: {:?}", e)
            )))
        }
    }
}

async fn unsubscribe_topic(
    matches: &ArgMatches,
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_hash = matches.value_of("TOPIC_HASH").unwrap();
    info!("Unsubscribing from topic: {}", topic_hash);
    
    // Check if subscribed
    let local_topics = load_topics(config)?;
    let existing = local_topics.iter().find(|t| t.hash == topic_hash);
    
    let is_subscribed = existing.map_or(false, |t| t.subscribed);
    
    if !is_subscribed {
        println!("Not currently subscribed to topic: {}", topic_hash);
        info!("Not subscribed to topic: {}", topic_hash);
        return Ok(());
    }
    
    // Unsubscribe on server
    println!("Unsubscribing from topic: {}", topic_hash);
    
    match server_connection.unsubscribe_from_topic(topic_hash).await {
        Ok(()) => {
            println!("Unsubscribed from topic successfully");
            info!("Unsubscribed from topic successfully");
            
            // Update local storage
            if let Some(existing) = existing {
                // Create updated copy with subscription flag changed
                let mut updated = existing.clone();
                updated.subscribed = false;
                store_topic(config, &updated)?;
            }
            
            Ok(())
        },
        Err(e) => {
            println!("Failed to unsubscribe from topic: {:?}", e);
            error!("Failed to unsubscribe from topic: {:?}", e);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to unsubscribe from topic: {:?}", e)
            )))
        }
    }
}

async fn publish_topic(
    matches: &ArgMatches,
    server_connection: &ServerConnection,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let topic_hash = matches.value_of("TOPIC_HASH").unwrap();
    let message = matches.value_of("MESSAGE").unwrap();
    
    info!("Publishing message to topic: {}", topic_hash);
    debug!("Message length: {} bytes", message.len());
    
    // Check if topic exists locally
    let local_topics = load_topics(config)?;
    let existing = local_topics.iter().find(|t| t.hash == topic_hash);
    
    if existing.is_none() {
        println!("Warning: Publishing to unknown topic: {}", topic_hash);
        warn!("Publishing to unknown topic: {}", topic_hash);
    }
    
    // Create a simple JSON structure for the topic message
    #[derive(Serialize)]
    struct TopicMessage {
        text: String,
        sender: String,
        timestamp: u64,
    }
    
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let topic_msg = TopicMessage {
        text: message.to_string(),
        sender: "anonymous".to_string(), // For privacy, don't include sender info
        timestamp: current_time,
    };
    
    let serialized = serde_json::to_vec(&topic_msg)?;
    
    // Publish to topic
    println!("Publishing message to topic: {}", topic_hash);
    
    match server_connection.publish_to_topic(topic_hash, &serialized, None).await {
        Ok(id) => {
            println!("Message published successfully with ID: {}", id);
            info!("Message published to topic: {}, ID: {}", topic_hash, id);
            Ok(())
        },
        Err(e) => {
            println!("Failed to publish message to topic: {:?}", e);
            error!("Failed to publish message to topic: {:?}", e);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to publish message: {:?}", e)
            )))
        }
    }
}

// Helper functions for topic storage

fn store_topic(config: &Config, topic: &StoredTopic) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Storing topic: {}", topic.hash);
    
    let topics_dir = config.get_topics_path();
    if !topics_dir.exists() {
        fs::create_dir_all(&topics_dir)?;
    }
    
    let topic_path = topics_dir.join(format!("{}.json", topic.hash));
    let serialized = serde_json::to_string_pretty(topic)?;
    
    let mut file = File::create(topic_path)?;
    file.write_all(serialized.as_bytes())?;
    
    debug!("Topic stored successfully");
    Ok(())
}

fn load_topics(config: &Config) -> Result<Vec<StoredTopic>, Box<dyn std::error::Error>> {
    debug!("Loading stored topics");
    
    let topics_dir = config.get_topics_path();
    if !topics_dir.exists() {
        debug!("Topics directory doesn't exist");
        return Ok(Vec::new());
    }
    
    let mut topics = Vec::new();
    
    for entry in std::fs::read_dir(topics_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            debug!("Loading topic from: {:?}", path);
            
            let mut file = File::open(&path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            
            match serde_json::from_str::<StoredTopic>(&content) {
                Ok(topic) => {
                    topics.push(topic);
                },
                Err(e) => {
                    warn!("Failed to parse topic file: {:?}, error: {:?}", path, e);
                }
            }
        }
    }
    
    debug!("Loaded {} topics", topics.len());
    Ok(topics)
}