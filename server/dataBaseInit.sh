-- Initialize secnet database schema

-- Public keys directory (minimal identification)
CREATE TABLE public_keys (
    public_key_hash BYTEA PRIMARY KEY,         -- Hash of combined public keys as identifier
    ed25519_public_key BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    last_active TIMESTAMP,                     -- Only track when last active, not online status
    connection_token UUID NOT NULL             -- Token for connection, not linked to identity
);

-- Prekeys table (for initial key exchange)
CREATE TABLE prekeys (
    id SERIAL PRIMARY KEY,
    public_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash),
    key_id BYTEA NOT NULL,                     -- Random ID instead of sequential
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    UNIQUE (public_key_hash, key_id)
);

-- Pending messages table (minimal metadata)
CREATE TABLE pending_messages (
    id BYTEA PRIMARY KEY,                      -- Random ID, not sequential
    recipient_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash),
    encrypted_content BYTEA NOT NULL,
    -- No sender reference stored
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL,                 -- Auto-delete after expiry
    is_delivered BOOLEAN DEFAULT FALSE
);

-- Topics table (anonymous)
CREATE TABLE topics (
    id BYTEA PRIMARY KEY,                      -- Hash of topic, not UUID
    -- No descriptive topic name stored
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Topic subscriptions table (privacy-preserving)
CREATE TABLE topic_subscriptions (
    topic_id BYTEA NOT NULL REFERENCES topics(id),
    subscriber_token BYTEA NOT NULL,           -- Blinded token, not directly linked to public key
    routing_data BYTEA NOT NULL,               -- Encrypted routing information
    PRIMARY KEY (topic_id, subscriber_token)
);

-- Topic messages table
CREATE TABLE topic_messages (
    id BYTEA PRIMARY KEY,                      -- Random ID, not sequential
    topic_id BYTEA NOT NULL REFERENCES topics(id),
    encrypted_content BYTEA NOT NULL,
    -- No sender reference stored
    posted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL                  -- Auto-delete after expiry
);

-- Message delivery tracking (minimal)
CREATE TABLE message_delivery (
    message_id BYTEA NOT NULL,
    recipient_token BYTEA NOT NULL,            -- Hashed token, not direct reference
    is_delivered BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (message_id, recipient_token)
);

-- Create indexes for performance
CREATE INDEX idx_pending_messages_recipient ON pending_messages(recipient_key_hash);
CREATE INDEX idx_pending_messages_delivery ON pending_messages(is_delivered);
CREATE INDEX idx_topic_messages_topic ON topic_messages(topic_id);
CREATE INDEX idx_prekeys_pubkey_used ON prekeys(public_key_hash, is_used);

-- Create a function to auto-delete expired messages
CREATE OR REPLACE FUNCTION delete_expired_messages() RETURNS void AS $$
BEGIN
    -- Delete expired pending messages
    DELETE FROM pending_messages WHERE expiry < NOW();
    
    -- Delete expired topic messages
    DELETE FROM topic_messages WHERE expiry < NOW();
    
    -- Clean up delivery tracking for deleted messages
    DELETE FROM message_delivery 
    WHERE message_id NOT IN (SELECT id FROM pending_messages)
      AND message_id NOT IN (SELECT id FROM topic_messages);
END;
$$ LANGUAGE plpgsql;

-- Create a function to clean up unused prekeys
CREATE OR REPLACE FUNCTION cleanup_used_prekeys() RETURNS void AS $$
BEGIN
    -- Keep only the most recent 10 used prekeys per public key
    DELETE FROM prekeys
    WHERE is_used = TRUE
      AND id NOT IN (
          SELECT id FROM (
              SELECT id,
                     ROW_NUMBER() OVER (PARTITION BY public_key_hash ORDER BY id DESC) as rn
              FROM prekeys
              WHERE is_used = TRUE
          ) AS recent_used
          WHERE rn <= 10
      );
END;
$$ LANGUAGE plpgsql;

-- Create database role for the server application
DO
$do$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'secnet_server') THEN
      CREATE ROLE secnet_server WITH LOGIN PASSWORD 'server_password';
   END IF;
END
$do$;

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secnet_server;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO secnet_server;
GRANT EXECUTE ON FUNCTION delete_expired_messages() TO secnet_server;
GRANT EXECUTE ON FUNCTION cleanup_used_prekeys() TO secnet_server;

-- For development/testing only (remove in production)
GRANT ALL PRIVILEGES ON DATABASE secnet TO secnetuser;