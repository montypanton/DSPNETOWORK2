// client/src/storage/config.rs
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use log::{debug, error, info, trace, warn};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub storage_path: PathBuf,
    pub connection_token: Option<String>,
    pub last_server_sync: Option<u64>,
    pub auto_fetch_messages: bool,
    pub message_fetch_interval: u64, // in seconds
}

impl Default for Config {
    fn default() -> Self {
        let mut storage_path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        storage_path.push("secnet");
        
        Config {
            server_url: "https://localhost:8080".to_string(),
            storage_path,
            connection_token: None,
            last_server_sync: None,
            auto_fetch_messages: true,
            message_fetch_interval: 60,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    IoError(std::io::Error),
    SerializationError(serde_json::Error),
    InvalidPath,
}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        ConfigError::IoError(err)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        ConfigError::SerializationError(err)
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        info!("Loading configuration from: {:?}", path);
        
        if !path.exists() {
            debug!("Config file does not exist, using defaults");
            return Ok(Config::default());
        }
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                debug!("Creating parent directory: {:?}", parent);
                fs::create_dir_all(parent)?;
            }
        }
        
        // Read the file
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        // Parse JSON
        let config: Config = serde_json::from_str(&contents)?;
        
        debug!("Config loaded successfully with server URL: {}", config.server_url);
        Ok(config)
    }
    
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        info!("Saving configuration to: {:?}", path);
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                debug!("Creating parent directory: {:?}", parent);
                fs::create_dir_all(parent)?;
            }
        } else {
            error!("Invalid config path: {:?}", path);
            return Err(ConfigError::InvalidPath);
        }
        
        // Serialize to JSON
        let json = serde_json::to_string_pretty(self)?;
        
        // Write to file
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        
        debug!("Config saved successfully");
        Ok(())
    }
    
    pub fn update_server_url(&mut self, url: &str) -> &mut Self {
        info!("Updating server URL to: {}", url);
        self.server_url = url.to_string();
        self
    }
    
    pub fn update_connection_token(&mut self, token: &str) -> &mut Self {
        info!("Updating connection token");
        trace!("New token: {}", token);
        self.connection_token = Some(token.to_string());
        self
    }
    
    pub fn update_last_sync(&mut self, timestamp: u64) -> &mut Self {
        debug!("Updating last server sync timestamp to: {}", timestamp);
        self.last_server_sync = Some(timestamp);
        self
    }
    
    pub fn set_auto_fetch(&mut self, enabled: bool) -> &mut Self {
        info!("Setting auto-fetch messages to: {}", enabled);
        self.auto_fetch_messages = enabled;
        self
    }
    
    pub fn set_fetch_interval(&mut self, interval: u64) -> &mut Self {
        info!("Setting message fetch interval to: {} seconds", interval);
        self.message_fetch_interval = interval;
        self
    }
    
    pub fn get_keys_path(&self) -> PathBuf {
        let mut path = self.storage_path.clone();
        path.push("keys");
        path
    }
    
    pub fn get_messages_path(&self) -> PathBuf {
        let mut path = self.storage_path.clone();
        path.push("messages");
        path
    }
    
    pub fn get_topics_path(&self) -> PathBuf {
        let mut path = self.storage_path.clone();
        path.push("topics");
        path
    }
    
    pub fn ensure_directories_exist(&self) -> Result<(), ConfigError> {
        info!("Ensuring all storage directories exist");
        
        let dirs = [
            self.storage_path.as_path(),
            self.get_keys_path().as_path(),
            self.get_messages_path().as_path(),
            self.get_topics_path().as_path(),
        ];
        
        for dir in &dirs {
            if !dir.exists() {
                debug!("Creating directory: {:?}", dir);
                fs::create_dir_all(dir)?;
            }
        }
        
        debug!("All directories exist");
        Ok(())
    }
}