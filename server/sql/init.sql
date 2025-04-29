-- Database schema for secnet server

-- Public keys table
CREATE TABLE public_keys (
    public_key_hash BYTEA PRIMARY KEY,
    ed25519_public_key BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    connection_token UUID NOT NULL,
    last_active TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Prekeys table
CREATE TABLE prekeys (
    id SERIAL PRIMARY KEY,
    public_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash),
    key_id BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (public_key_hash, key_id)
);

-- Pending messages table
CREATE TABLE pending_messages (
    id BYTEA PRIMARY KEY,
    recipient_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash),
    encrypted_content BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL,
    is_delivered BOOLEAN NOT NULL DEFAULT FALSE
);

-- Topics table
CREATE TABLE topics (
    id BYTEA PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Topic subscriptions table
CREATE TABLE topic_subscriptions (
    id SERIAL PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id),
    subscriber_token BYTEA NOT NULL,
    routing_data BYTEA NOT NULL,
    UNIQUE (topic_id, subscriber_token)
);

-- Topic messages table
CREATE TABLE topic_messages (
    id BYTEA PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id),
    encrypted_content BYTEA NOT NULL,
    posted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL
);

-- Message delivery tracking table
CREATE TABLE message_delivery (
    id SERIAL PRIMARY KEY,
    message_id BYTEA NOT NULL REFERENCES topic_messages(id),
    recipient_token BYTEA NOT NULL,
    is_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (message_id, recipient_token)
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