// client/src/cli/commands/peer.rs
use clap::ArgMatches;
use log::{debug, error, info, trace, warn};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use prettytable::{Table, Row, Cell};

use crate::crypto::keys::KeyManager;
use crate::storage::config::Config;

pub async fn execute(matches: &ArgMatches, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Executing peer command");
    
    // Ensure storage directories exist
    config.ensure_directories_exist()?;
    
    // Initialize key manager
    let keys_path = config.get_keys_path().to_string_lossy().to_string();
    let mut key_manager = KeyManager::new(&keys_path)?;
    
    // Check if we have our own identity
    if key_manager.get_identity().is_none() {
        println!("No identity keys found. Run 'secnet keygen' first.");
        error!("No identity keys found for peer command");
        return Err("No identity keys found".into());
    }
    
    match matches.subcommand() {
        ("list", Some(_)) => {
            list_peers(&key_manager)?;
        },
        ("add", Some(sub_m)) => {
            add_peer(sub_m, &mut key_manager)?;
        },
        ("verify", Some(sub_m)) => {
            verify_peer(sub_m, &key_manager)?;
        },
        ("remove", Some(sub_m)) => {
            remove_peer(sub_m, &mut key_manager)?;
        },
        _ => {
            println!("Unknown peer subcommand. Use --help for usage information.");
            info!("Unknown peer subcommand specified");
        }
    }
    
    info!("Peer command completed successfully");
    Ok(())
}

fn list_peers(key_manager: &KeyManager) -> Result<(), Box<dyn std::error::Error>> {
    info!("Listing known peers");
    
    let peers = key_manager.get_peers();
    
    if peers.is_empty() {
        println!("No peers found.");
        debug!("No peers found in key manager");
        return Ok(());
    }
    
    println!("Found {} peers:", peers.len());
    info!("Found {} peers", peers.len());
    
    // Create a table for pretty output
    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Fingerprint"),
        Cell::new("Alias"),
        Cell::new("Key Type"),
    ]));
    
    for (fingerprint, peer) in peers {
        let alias = peer.alias.as_deref().unwrap_or("(no alias)");
        
        table.add_row(Row::new(vec![
            Cell::new(&fingerprint),
            Cell::new(alias),
            Cell::new("Ed25519/X25519/Kyber"),
        ]));
        
        trace!("Peer: fingerprint={}, alias={}", fingerprint, alias);
    }
    
    // Print the table
    table.printstd();
    
    debug!("Peer list displayed successfully");
    Ok(())
}

fn add_peer(matches: &ArgMatches, key_manager: &mut KeyManager) -> Result<(), Box<dyn std::error::Error>> {
    info!("Adding new peer");
    
    let key_file = matches.value_of("key-file");
    let alias = matches.value_of("alias").map(|s| s.to_string());
    
    debug!("Peer add options - Key file: {:?}, Alias: {:?}", key_file, alias);
    
    // Read public key from file
    let key_data = if let Some(file_path) = key_file {
        println!("Reading public key from file: {}", file_path);
        info!("Reading public key from file: {}", file_path);
        
        let mut file = File::open(file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        
        debug!("Read {} bytes from key file", data.len());
        data
    } else {
        // No key file specified, prompt for pasting
        println!("No key file specified. Please paste the peer's public key (Base64 encoded):");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        // Attempt to decode Base64
        match base64::decode(input.trim()) {
            Ok(decoded) => {
                debug!("Decoded Base64 key, {} bytes", decoded.len());
                decoded
            },
            Err(_) => {
                // Maybe it's already raw JSON
                debug!("Not valid Base64, treating as raw JSON");
                input.trim().as_bytes().to_vec()
            }
        }
    };
    
    // Import peer key
    match key_manager.import_peer_key(&key_data, alias) {
        Ok(fingerprint) => {
            println!("Peer added successfully with fingerprint: {}", fingerprint);
            info!("Peer added successfully: {}", fingerprint);
            
            // Print alias if present
            if let Some(peer) = key_manager.get_peer(&fingerprint) {
                if let Some(alias) = &peer.alias {
                    println!("Assigned alias: {}", alias);
                }
            }
            
            println!("\nRemember to verify this fingerprint with your peer out-of-band!");
            println!("Run 'secnet peer verify {}' to confirm", fingerprint);
            
            Ok(())
        },
        Err(e) => {
            println!("Failed to add peer: {:?}", e);
            error!("Failed to add peer: {:?}", e);
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to add peer: {:?}", e))))
        }
    }
}

fn verify_peer(matches: &ArgMatches, key_manager: &KeyManager) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint = matches.value_of("FINGERPRINT").unwrap();
    info!("Verifying peer fingerprint: {}", fingerprint);
    
    // Check if peer exists
    match key_manager.get_peer(fingerprint) {
        Some(peer) => {
            println!("Peer found with fingerprint: {}", fingerprint);
            
            // Print peer information
            println!("\nKey information:");
            println!("Fingerprint: {}", fingerprint);
            if let Some(alias) = &peer.alias {
                println!("Alias: {}", alias);
            }
            
            println!("\nVerify that this fingerprint matches the one provided by your peer.");
            println!("If it matches, you can trust this peer for secure communications.");
            
            // For a real application, we would offer more verification options
            // Such as QR codes, safety numbers, emojis, etc.
            
            info!("Peer verification information displayed");
            Ok(())
        },
        None => {
            println!("No peer found with fingerprint: {}", fingerprint);
            error!("No peer found with fingerprint: {}", fingerprint);
            Err("Peer not found".into())
        }
    }
}

fn remove_peer(matches: &ArgMatches, key_manager: &mut KeyManager) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint = matches.value_of("FINGERPRINT").unwrap();
    info!("Removing peer with fingerprint: {}", fingerprint);
    
    // Check if peer exists first
    if key_manager.get_peer(fingerprint).is_none() {
        println!("No peer found with fingerprint: {}", fingerprint);
        error!("No peer found with fingerprint: {}", fingerprint);
        return Err("Peer not found".into());
    }
    
    // Ask for confirmation
    println!("Are you sure you want to remove peer with fingerprint: {}? (y/N)", fingerprint);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() != "y" {
        println!("Peer removal cancelled.");
        info!("Peer removal cancelled by user");
        return Ok(());
    }
    
    // Remove peer
    match key_manager.remove_peer(fingerprint) {
        Ok(()) => {
            println!("Peer removed successfully.");
            info!("Peer removed successfully: {}", fingerprint);
            Ok(())
        },
        Err(e) => {
            println!("Failed to remove peer: {:?}", e);
            error!("Failed to remove peer: {:?}", e);
            Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to remove peer: {:?}", e))))
        }
    }
}