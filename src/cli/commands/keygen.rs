// client/src/cli/commands/keygen.rs
use clap::ArgMatches;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::crypto::keys::KeyManager;
use crate::network::connection::ServerConnection;
use crate::storage::config::Config;

pub async fn execute(matches: &ArgMatches, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Executing keygen command");
    
    // Extract command arguments
    let server_url = matches.value_of("server").unwrap_or(&config.server_url);
    let alias = matches.value_of("alias").map(|s| s.to_string());
    let export_file = matches.value_of("export-pub").map(Path::new);
    let rotate = matches.is_present("rotate");
    let backup_file = matches.value_of("backup").map(Path::new);
    
    debug!("Keygen options - Server URL: {}, Alias: {:?}, Export: {:?}, Rotate: {}, Backup: {:?}",
           server_url, alias, export_file, rotate, backup_file);
    
    // Update config if server URL changed
    let mut config = config.clone();
    if server_url != config.server_url {
        info!("Updating server URL to: {}", server_url);
        config.update_server_url(server_url);
    }
    
    // Ensure storage directories exist
    config.ensure_directories_exist()?;
    
    // Initialize key manager
    let keys_path = config.get_keys_path().to_string_lossy().to_string();
    let mut key_manager = KeyManager::new(&keys_path)?;
    
    // Generate or rotate keys
    if rotate {
        if let Some(existing_identity) = key_manager.get_identity() {
            println!("Rotating existing identity keys with fingerprint: {}", existing_identity.fingerprint);
            info!("Rotating existing identity keys");
            
            // In a real implementation, we would perform a proper key rotation
            // For this simulation, we'll just generate new keys
            let identity = key_manager.generate_identity_keys(
                alias.or_else(|| existing_identity.alias.clone())
            )?;
            
            println!("New identity keys generated with fingerprint: {}", identity.fingerprint);
            info!("New identity keys generated: {}", identity.fingerprint);
        } else {
            println!("No existing identity keys found, generating new ones");
            warn!("Rotate specified but no existing keys found");
            
            let identity = key_manager.generate_identity_keys(alias)?;
            println!("New identity keys generated with fingerprint: {}", identity.fingerprint);
            info!("New identity keys generated: {}", identity.fingerprint);
        }
    } else if key_manager.get_identity().is_none() {
        println!("Generating new identity keys...");
        info!("Generating new identity keys");
        
        let identity = key_manager.generate_identity_keys(alias)?;
        println!("Identity keys generated with fingerprint: {}", identity.fingerprint);
        if let Some(alias) = &identity.alias {
            println!("Using alias: {}", alias);
        }
        
        info!("New identity keys generated: {}", identity.fingerprint);
    } else {
        println!("Identity keys already exist. Use --rotate to generate new ones.");
        info!("Identity keys already exist, not generating new ones");
        
        // If alias is provided, update it
        if let Some(alias_str) = alias {
            // In a real implementation, we would have a method to update the alias
            // For this simulation, we'll just note that it would be updated
            println!("Note: Alias updates not implemented in this version");
            info!("Alias update requested but not implemented");
        }
    }
    
    // Get the current identity
    let identity = match key_manager.get_identity() {
        Some(identity) => identity,
        None => {
            error!("No identity keys available after keygen operation");
            return Err("No identity keys available".into());
        }
    };
    
    // Export public key if requested
    if let Some(export_path) = export_file {
        println!("Exporting public key to: {:?}", export_path);
        info!("Exporting public key to: {:?}", export_path);
        
        let public_key_data = key_manager.export_public_key()?;
        let mut file = File::create(export_path)?;
        file.write_all(&public_key_data)?;
        
        println!("Public key exported successfully");
        debug!("Public key exported successfully, size: {} bytes", public_key_data.len());
    }
    
    // Create backup if requested
    if let Some(backup_path) = backup_file {
        println!("Creating encrypted backup to: {:?}", backup_path);
        println!("Enter backup password: ");
        let password = rpassword::read_password()?;
        
        info!("Creating encrypted backup to: {:?}", backup_path);
        key_manager.backup_keys(backup_path.to_str().unwrap(), &password)?;
        
        println!("Backup created successfully");
        info!("Backup created successfully");
    }
    
    // Initialize server connection and announce keys
    println!("Connecting to server at: {}", server_url);
    info!("Connecting to server at: {}", server_url);
    
    let server_connection = ServerConnection::new(config.clone(), Some(identity.clone()))?;
    
    // Announce keys to server
    println!("Announcing public keys to server...");
    info!("Announcing public keys to server");
    
    match server_connection.clone().announce().await {
        Ok(token) => {
            println!("Successfully connected and registered with server");
            info!("Successfully registered with server");
            debug!("Received connection token: {}", token);
            
            // Update connection token in config
            let mut updated_config = config.clone();
            updated_config.update_connection_token(&token);
            
            // Save config
            let config_path = Path::new(&config.storage_path).join("config.json");
            if let Err(e) = updated_config.save(&config_path) {
                error!("Failed to save config: {}", e);
                return Err(Box::new(e));
            }
            
            debug!("Updated config saved successfully");
        },
        Err(e) => {
            println!("Failed to announce keys to server: {:?}", e);
            error!("Failed to announce keys to server: {:?}", e);
            // Continue anyway since keys were generated
        }
    }
    
    // Upload prekeys
    println!("Uploading prekeys to server...");
    info!("Uploading prekeys to server");
    
    match server_connection.upload_prekeys(key_manager.get_prekeys()).await {
        Ok(count) => {
            println!("{} prekeys uploaded successfully", count);
            info!("{} prekeys uploaded successfully", count);
        },
        Err(e) => {
            println!("Failed to upload prekeys: {:?}", e);
            error!("Failed to upload prekeys: {:?}", e);
            // Continue anyway since keys were generated
        }
    }
    
    // Print fingerprint and completion message
    println!("\nKey generation completed successfully");
    println!("Identity fingerprint: {}", identity.fingerprint);
    if let Some(alias) = &identity.alias {
        println!("Using alias: {}", alias);
    }
    println!("\nUse this fingerprint when others want to communicate with you");
    
    info!("Keygen command completed successfully");
    Ok(())
}