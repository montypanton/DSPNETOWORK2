-- Database schema for SecNet server
-- With enhanced security and privacy features

-- Public keys table
CREATE TABLE public_keys (
    public_key_hash BYTEA PRIMARY KEY,
    ed25519_public_key BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    connection_token UUID NOT NULL,
    last_active TIMESTAMP NOT NULL DEFAULT NOW(),
    registration_time TIMESTAMP NOT NULL DEFAULT NOW(),
    connection_count INTEGER NOT NULL DEFAULT 1,
    last_ip_hash BYTEA -- Hashed IP address for abuse prevention
);

-- Prekeys table
CREATE TABLE prekeys (
    id SERIAL PRIMARY KEY,
    public_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash) ON DELETE CASCADE,
    key_id BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    upload_time TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (public_key_hash, key_id)
);

-- Pending messages table with enhanced metadata protection
CREATE TABLE pending_messages (
    id BYTEA PRIMARY KEY,
    recipient_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash) ON DELETE CASCADE,
    encrypted_content BYTEA NOT NULL,
    hmac BYTEA NOT NULL, -- Integrity protection
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL,
    is_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    priority SMALLINT NOT NULL DEFAULT 1, -- Higher values = higher priority
    delivery_attempts SMALLINT NOT NULL DEFAULT 0, -- Count of delivery attempts
    metadata_obfuscation BYTEA -- Additional metadata obfuscation
);

-- Topics table with enhanced features
CREATE TABLE topics (
    id BYTEA PRIMARY KEY,
    topic_type VARCHAR(20) NOT NULL DEFAULT 'Public', -- Public, Private, Ephemeral
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP, -- NULL means never expires
    max_subscribers INTEGER NOT NULL DEFAULT 100,
    max_message_size INTEGER NOT NULL DEFAULT 10485760, -- 10MB default
    requires_auth BOOLEAN NOT NULL DEFAULT FALSE
);

-- Topic invitations for private topics
CREATE TABLE topic_invitations (
    id SERIAL PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    invitation_token BYTEA NOT NULL,
    capabilities SMALLINT NOT NULL DEFAULT 1, -- 1: read, 2: write, 4: admin
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_by BYTEA, -- Blinded token of user who used this invitation
    UNIQUE (topic_id, invitation_token)
);

-- Topic subscriptions table with enhanced privacy
CREATE TABLE topic_subscriptions (
    id SERIAL PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    subscriber_token BYTEA NOT NULL, -- Blinded token (cannot be linked to public_key_hash)
    routing_data BYTEA NOT NULL, -- Encrypted routing information
    capabilities SMALLINT NOT NULL DEFAULT 1, -- 1: read, 2: write, 4: admin
    join_time TIMESTAMP NOT NULL DEFAULT NOW(),
    last_active TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (topic_id, subscriber_token)
);

-- Topic messages table with integrity protection
CREATE TABLE topic_messages (
    id BYTEA PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    encrypted_content BYTEA NOT NULL,
    hmac BYTEA NOT NULL, -- Integrity protection
    posted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL,
    metadata BYTEA -- Optional encrypted metadata
);

-- Message delivery tracking table
CREATE TABLE message_delivery (
    id SERIAL PRIMARY KEY,
    message_id BYTEA NOT NULL REFERENCES topic_messages(id) ON DELETE CASCADE,
    recipient_token BYTEA NOT NULL, -- Blinded token
    is_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    delivery_time TIMESTAMP,
    UNIQUE (message_id, recipient_token)
);

-- Rate limiting table
CREATE TABLE rate_limits (
    id SERIAL PRIMARY KEY,
    token_hash BYTEA NOT NULL, -- Hashed token or IP
    action_type VARCHAR(50) NOT NULL, -- e.g., 'message_send', 'topic_create'
    count INTEGER NOT NULL DEFAULT 1,
    first_action TIMESTAMP NOT NULL DEFAULT NOW(),
    last_action TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (token_hash, action_type)
);

-- Function to delete expired messages
CREATE OR REPLACE FUNCTION delete_expired_messages() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM pending_messages
        WHERE expiry < NOW()
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up used prekeys
CREATE OR REPLACE FUNCTION cleanup_used_prekeys() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Keep at most 10 used prekeys per user
    WITH to_delete AS (
        SELECT id FROM (
            SELECT id, public_key_hash, 
                   ROW_NUMBER() OVER (PARTITION BY public_key_hash ORDER BY id DESC) as rn
            FROM prekeys
            WHERE is_used = TRUE
        ) ranked
        WHERE rn > 10
    ),
    deleted AS (
        DELETE FROM prekeys
        WHERE id IN (SELECT id FROM to_delete)
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to delete expired topics and related data
CREATE OR REPLACE FUNCTION delete_expired_topics() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM topics
        WHERE expires_at IS NOT NULL AND expires_at < NOW()
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to delete expired invitations
CREATE OR REPLACE FUNCTION delete_expired_invitations() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM topic_invitations
        WHERE expires_at < NOW() AND is_used = FALSE
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to delete expired topic messages
CREATE OR REPLACE FUNCTION delete_expired_topic_messages() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM topic_messages
        WHERE expiry < NOW()
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to reset rate limits
CREATE OR REPLACE FUNCTION reset_rate_limits() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH deleted AS (
        DELETE FROM rate_limits
        WHERE last_action < NOW() - INTERVAL '1 day'
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create indexes for better performance
CREATE INDEX idx_pending_messages_recipient ON pending_messages(recipient_key_hash);
CREATE INDEX idx_pending_messages_expiry ON pending_messages(expiry);
CREATE INDEX idx_topic_subscriptions_topic ON topic_subscriptions(topic_id);
CREATE INDEX idx_topic_messages_topic ON topic_messages(topic_id);
CREATE INDEX idx_topic_messages_expiry ON topic_messages(expiry);
CREATE INDEX idx_message_delivery_message ON message_delivery(message_id);
CREATE INDEX idx_rate_limits_token ON rate_limits(token_hash);

-- Create roles and permissions
CREATE ROLE secnet_service WITH LOGIN PASSWORD 'service_password';
CREATE ROLE secnet_admin WITH LOGIN PASSWORD 'admin_password';

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO secnet_service;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO secnet_service;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO secnet_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO secnet_admin;