// client/src/network/connection.rs
use log::{debug, error, info, trace, warn};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use tokio::time;

use crate::crypto::keys::{IdentityKeyBundle, PreKeyBundle};
use crate::storage::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub async fn fetch_messages(&self) -> Result<Vec<Message>, ConnectionError> {
        info!("Fetching pending messages");
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Send request to server
        let url = format!("{}/messages/{}", self.config.server_url, token);
        debug!("Fetching messages from URL: {}", url);
        
        let response = self.client
            .get(&url)
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK => {
                debug!("Message fetch successful, parsing response");
                let fetch_response: FetchMessagesResponse = response.json().await?;
                
                info!("Received {} pending messages", fetch_response.messages.len());
                if fetch_response.more_available {
                    debug!("More messages available on server");
                }
                
                Ok(fetch_response.messages)
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn acknowledge_message(&self, message_id: &str) -> Result<(), ConnectionError> {
        info!("Acknowledging message: {}", message_id);
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Send request to server
        let url = format!("{}/messages/{}", self.config.server_url, message_id);
        debug!("Acknowledging message at URL: {}", url);
        
        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {
                debug!("Message acknowledged successfully");
                Ok(())
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn refresh_connection_token(&mut self) -> Result<String, ConnectionError> {
        info!("Refreshing connection token");
        
        // Get current connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available to refresh");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Send request to server
        let url = format!("{}/connection/refresh", self.config.server_url);
        debug!("Refreshing token at URL: {}", url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK => {
                debug!("Token refresh successful, parsing response");
                let refresh_response: HashMap<String, String> = response.json().await?;
                
                let new_token = refresh_response.get("connection_token")
                    .ok_or(ConnectionError::InvalidResponse)?;
                
                info!("Received new connection token");
                trace!("New token: {}", new_token);
                
                // Update config with new token
                self.config.update_connection_token(new_token);
                
                Ok(new_token.clone())
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn create_topic(&self) -> Result<String, ConnectionError> {
        info!("Creating new topic");
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Send request to server
        let url = format!("{}/topics", self.config.server_url);
        debug!("Creating topic at URL: {}", url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                debug!("Topic created successfully, parsing response");
                let topic_response: TopicCreateResponse = response.json().await?;
                
                info!("Topic created with hash: {}", topic_response.topic_hash);
                Ok(topic_response.topic_hash)
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn list_topics(&self) -> Result<Vec<Topic>, ConnectionError> {
        info!("Listing available topics");
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Send request to server
        let url = format!("{}/topics", self.config.server_url);
        debug!("Listing topics from URL: {}", url);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK => {
                debug!("Topic list successful, parsing response");
                let topic_list: TopicListResponse = response.json().await?;
                
                info!("Received {} topics", topic_list.topics.len());
                Ok(topic_list.topics)
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn subscribe_to_topic(&self, topic_hash: &str, blinded: bool) -> Result<(), ConnectionError> {
        info!("Subscribing to topic: {}", topic_hash);
        if blinded {
            debug!("Using blinded subscription for privacy");
        }
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Get identity
        let identity = match &self.identity {
            Some(keys) => keys,
            None => {
                error!("No identity keys available for topic subscription");
                return Err(ConnectionError::NoIdentity);
            }
        };
        
        // Create blinded token if needed
        let subscriber_token = if blinded {
            // In a real implementation, we would create a proper blinded token
            // For simulation, we'll just create a random token
            let mut token = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut token);
            token.to_vec()
        } else {
            // Use a hash of our public key
            let mut hasher = sha2::Sha256::new();
            hasher.update(&identity.ed25519.public);
            hasher.finalize().to_vec()
        };
        
        // Create encrypted routing information
        // In a real implementation, this would be properly encrypted
        // For simulation, we'll just use a placeholder
        let routing_data = token.to_string().as_bytes().to_vec();
        
        // Create request
        let request = TopicSubscribeRequest {
            topic_hash: topic_hash.to_string(),
            subscriber_token,
            routing_data,
        };
        
        // Send request to server
        let url = format!("{}/topics/{}/subscribe", self.config.server_url, topic_hash);
        debug!("Subscribing to topic at URL: {}", url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                info!("Successfully subscribed to topic: {}", topic_hash);
                Ok(())
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn unsubscribe_from_topic(&self, topic_hash: &str) -> Result<(), ConnectionError> {
        info!("Unsubscribing from topic: {}", topic_hash);
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Send request to server
        let url = format!("{}/topics/{}/unsubscribe", self.config.server_url, topic_hash);
        debug!("Unsubscribing from topic at URL: {}", url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::NO_CONTENT => {
                info!("Successfully unsubscribed from topic: {}", topic_hash);
                Ok(())
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn publish_to_topic(&self, topic_hash: &str, encrypted_content: &[u8], ttl: Option<u64>) -> Result<String, ConnectionError> {
        info!("Publishing message to topic: {}", topic_hash);
        trace!("Message size: {} bytes", encrypted_content.len());
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Create request
        let request = SendTopicMessageRequest {
            topic_hash: topic_hash.to_string(),
            encrypted_content: encrypted_content.to_vec(),
            expiry: ttl.or(Some(86400)), // Default 24 hours TTL
        };
        
        // Send request to server
        let url = format!("{}/topics/{}/messages", self.config.server_url, topic_hash);
        debug!("Publishing to topic at URL: {}", url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                debug!("Message published successfully, parsing response");
                let send_response: SendMessageResponse = response.json().await?;
                
                info!("Topic message published, ID: {}", send_response.message_id);
                Ok(send_response.message_id)
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn fetch_messages_background(&self, interval_secs: u64) -> Result<(), ConnectionError> {
        info!("Starting background message fetching every {} seconds", interval_secs);
        
        let client = self.client.clone();
        let server_url = self.config.server_url.clone();
        let token = match &self.config.connection_token {
            Some(token) => token.clone(),
            None => {
                error!("No connection token available for background fetching");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Spawn background task
        tokio::spawn(async move {
            debug!("Background message fetching task started");
            let mut interval = time::interval(Duration::from_secs(interval_secs));
            
            loop {
                interval.tick().await;
                
                debug!("Fetching messages in background task");
                let url = format!("{}/messages/{}", server_url, token);
                
                match client.get(&url).send().await {
                    Ok(response) => {
                        match response.status() {
                            StatusCode::OK => {
                                match response.json::<FetchMessagesResponse>().await {
                                    Ok(fetch_response) => {
                                        info!("Background task: Received {} messages", 
                                              fetch_response.messages.len());
                                        
                                        // In a real implementation, we would process these messages
                                        // For simulation, we just log them
                                        if !fetch_response.messages.is_empty() {
                                            debug!("Background task: Messages need processing");
                                            // Signal main thread somehow
                                        }
                                    },
                                    Err(e) => {
                                        error!("Background task: Failed to parse response: {}", e);
                                    }
                                }
                            },
                            status => {
                                error!("Background task: Server returned error: {}", status);
                                if status == StatusCode::UNAUTHORIZED {
                                    error!("Background task: Authentication invalid, stopping");
                                    break;
                                }
                            }
                        }
                    },
                    Err(e) => {
                        error!("Background task: Network error: {}", e);
                        // Back off for a while if there's a network error
                        time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }
            
            warn!("Background message fetching task stopped");
        });
        
        info!("Background message fetching task spawned");
        Ok(())
    }
    
    pub async fn check_server_connection(&self) -> Result<bool, ConnectionError> {
        debug!("Checking server connection status");
        
        // Send a simple ping request
        let url = format!("{}/connection/ping", self.config.server_url);
        
        match self.client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                debug!("Server responded with status: {}", status);
                
                if status.is_success() {
                    info!("Server connection is active");
                    Ok(true)
                } else {
                    warn!("Server connection check failed with status: {}", status);
                    Ok(false)
                }
            },
            Err(e) => {
                error!("Server connection check failed with error: {}", e);
                Err(ConnectionError::NetworkError(e))
            }
        }
    }
} id: String,
    pub recipient_key_hash: String,
    pub encrypted_content: Vec<u8>,
    pub expiry: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicMessage {
    pub id: String,
    pub topic_hash: String,
    pub encrypted_content: Vec<u8>,
    pub posted_at: u64,
    pub expiry: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Topic {
    pub hash: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnnouncementRequest {
    pub ed25519_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub kyber_public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnnouncementResponse {
    pub connection_token: String,
    pub public_key_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeysUploadRequest {
    pub public_key_hash: String,
    pub prekeys: Vec<PreKeyBundle>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreKeysResponse {
    pub status: String,
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub recipient_key_hash: String,
    pub encrypted_content: Vec<u8>,
    pub expiry: Option<u64>, // Optional TTL in seconds
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMessagesResponse {
    pub messages: Vec<Message>,
    pub more_available: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicCreateResponse {
    pub topic_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicListResponse {
    pub topics: Vec<Topic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopicSubscribeRequest {
    pub topic_hash: String,
    pub subscriber_token: Vec<u8>,
    pub routing_data: Vec<u8>, // Encrypted routing information
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTopicMessageRequest {
    pub topic_hash: String,
    pub encrypted_content: Vec<u8>,
    pub expiry: Option<u64>, // Optional TTL in seconds
}

#[derive(Debug)]
pub enum ConnectionError {
    NetworkError(reqwest::Error),
    ServerError(String),
    AuthenticationError,
    SerializationError(serde_json::Error),
    InvalidResponse,
    NoConnectionToken,
    NoIdentity,
}

impl From<reqwest::Error> for ConnectionError {
    fn from(err: reqwest::Error) -> Self {
        ConnectionError::NetworkError(err)
    }
}

impl From<serde_json::Error> for ConnectionError {
    fn from(err: serde_json::Error) -> Self {
        ConnectionError::SerializationError(err)
    }
}

pub struct ServerConnection {
    client: Client,
    config: Config,
    identity: Option<IdentityKeyBundle>,
}

impl ServerConnection {
    pub fn new(config: Config, identity: Option<IdentityKeyBundle>) -> Result<Self, ConnectionError> {
        info!("Initializing server connection to: {}", config.server_url);
        
        // Create HTTP client with reasonable timeout and extra settings
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("secnet/0.1.0")
            .build()?;
        
        debug!("HTTP client initialized");
        
        Ok(ServerConnection {
            client,
            config,
            identity,
        })
    }
    
    pub async fn announce(&mut self) -> Result<String, ConnectionError> {
        info!("Announcing public keys to server");
        
        // Get identity key bundle
        let identity = match &self.identity {
            Some(keys) => keys,
            None => {
                error!("No identity keys available for announcement");
                return Err(ConnectionError::NoIdentity);
            }
        };
        
        // Create announcement request
        let request = AnnouncementRequest {
            ed25519_public_key: identity.ed25519.public.clone(),
            x25519_public_key: identity.x25519.public.clone(),
            kyber_public_key: identity.kyber.public.0.clone(),
        };
        
        // Send request to server
        let url = format!("{}/announce", self.config.server_url);
        debug!("Sending announcement to URL: {}", url);
        
        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK => {
                debug!("Announcement successful, parsing response");
                let announcement: AnnouncementResponse = response.json().await?;
                
                info!("Received connection token from server");
                trace!("Connection token: {}", announcement.connection_token);
                trace!("Public key hash: {}", announcement.public_key_hash);
                
                // Update config with connection token
                self.config.update_connection_token(&announcement.connection_token);
                
                Ok(announcement.connection_token)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn upload_prekeys(&self, prekeys: &[PreKeyBundle]) -> Result<usize, ConnectionError> {
        info!("Uploading {} prekeys to server", prekeys.len());
        
        // Get public key hash
        let identity = match &self.identity {
            Some(keys) => keys,
            None => {
                error!("No identity keys available for prekey upload");
                return Err(ConnectionError::NoIdentity);
            }
        };
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Create upload request
        let request = PreKeysUploadRequest {
            public_key_hash: identity.fingerprint.clone(),
            prekeys: prekeys.to_vec(),
        };
        
        // Send request to server
        let url = format!("{}/prekeys", self.config.server_url);
        debug!("Uploading prekeys to URL: {}", url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK => {
                debug!("Prekey upload successful, parsing response");
                let prekey_response: PreKeysResponse = response.json().await?;
                
                info!("Server accepted {} prekeys", prekey_response.count);
                Ok(prekey_response.count)
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn fetch_prekeys(&self, peer_key_hash: &str) -> Result<Vec<PreKeyBundle>, ConnectionError> {
        info!("Fetching prekeys for peer: {}", peer_key_hash);
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Send request to server
        let url = format!("{}/prekeys/{}", self.config.server_url, peer_key_hash);
        debug!("Fetching prekeys from URL: {}", url);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK => {
                debug!("Prekey fetch successful, parsing response");
                let prekeys: Vec<PreKeyBundle> = response.json().await?;
                
                info!("Received {} prekeys for peer", prekeys.len());
                trace!("First prekey ID: {:?}", prekeys.first().map(|pk| hex::encode(&pk.key_id)));
                
                Ok(prekeys)
            },
            StatusCode::NOT_FOUND => {
                warn!("No prekeys found for peer: {}", peer_key_hash);
                Ok(Vec::new())
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub async fn send_message(&self, recipient_key_hash: &str, encrypted_content: &[u8], ttl: Option<u64>) -> Result<String, ConnectionError> {
        info!("Sending message to recipient: {}", recipient_key_hash);
        trace!("Message size: {} bytes", encrypted_content.len());
        
        // Get connection token
        let token = match &self.config.connection_token {
            Some(token) => token,
            None => {
                error!("No connection token available");
                return Err(ConnectionError::NoConnectionToken);
            }
        };
        
        // Create request
        let request = SendMessageRequest {
            recipient_key_hash: recipient_key_hash.to_string(),
            encrypted_content: encrypted_content.to_vec(),
            expiry: ttl.or(Some(86400)), // Default 24 hours TTL
        };
        
        // Send request to server
        let url = format!("{}/messages", self.config.server_url);
        debug!("Sending message to URL: {}", url);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await?;
        
        // Handle response
        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                debug!("Message sent successfully, parsing response");
                let send_response: SendMessageResponse = response.json().await?;
                
                info!("Message sent, ID: {}", send_response.message_id);
                Ok(send_response.message_id)
            },
            StatusCode::UNAUTHORIZED => {
                error!("Server rejected authentication");
                Err(ConnectionError::AuthenticationError)
            },
            status => {
                error!("Server returned error: {}", status);
                Err(ConnectionError::ServerError(format!("Server returned {}", status)))
            }
        }
    }
    
    pub
