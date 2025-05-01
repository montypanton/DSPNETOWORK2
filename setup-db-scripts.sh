#!/bin/bash
set -e

echo "Setting up database initialization scripts..."

# Ensure SQL directories exist
mkdir -p server/sql

# Ensure init.sql exists or create it
if [ ! -f server/sql/init.sql ]; then
    # Copy from existing file or create a basic one
    if [ -f server/sql/complete-schema-fix.sql ]; then
        cp server/sql/complete-schema-fix.sql server/sql/init.sql
    else
        cat > server/sql/init.sql << EOF
-- Initial database schema for SecNet server
CREATE TABLE IF NOT EXISTS public_keys (
    public_key_hash BYTEA PRIMARY KEY,
    ed25519_public_key BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    connection_token UUID NOT NULL,
    last_active TIMESTAMP NOT NULL DEFAULT NOW(),
    registration_time TIMESTAMP NOT NULL DEFAULT NOW(),
    connection_count INTEGER NOT NULL DEFAULT 1,
    last_ip_hash BYTEA
);

CREATE TABLE IF NOT EXISTS pending_messages (
    id BYTEA PRIMARY KEY,
    recipient_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash) ON DELETE CASCADE,
    encrypted_content BYTEA NOT NULL,
    hmac BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL,
    is_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    priority SMALLINT NOT NULL DEFAULT 1,
    delivery_attempts SMALLINT NOT NULL DEFAULT 0,
    metadata_obfuscation BYTEA
);

CREATE TABLE IF NOT EXISTS topics (
    id BYTEA PRIMARY KEY,
    topic_type VARCHAR(20) NOT NULL DEFAULT 'Public',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    max_subscribers INTEGER NOT NULL DEFAULT 100,
    max_message_size INTEGER NOT NULL DEFAULT 10485760,
    requires_auth BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS topic_subscriptions (
    id SERIAL PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    subscriber_token BYTEA NOT NULL,
    routing_data BYTEA NOT NULL,
    capabilities SMALLINT NOT NULL DEFAULT 1,
    join_time TIMESTAMP NOT NULL DEFAULT NOW(),
    last_active TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (topic_id, subscriber_token)
);

CREATE TABLE IF NOT EXISTS topic_messages (
    id BYTEA PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    encrypted_content BYTEA NOT NULL,
    hmac BYTEA NOT NULL,
    posted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL,
    metadata BYTEA
);

CREATE TABLE IF NOT EXISTS message_delivery (
    id SERIAL PRIMARY KEY,
    message_id BYTEA NOT NULL REFERENCES topic_messages(id) ON DELETE CASCADE,
    recipient_token BYTEA NOT NULL,
    is_delivered BOOLEAN NOT NULL DEFAULT FALSE,
    delivery_time TIMESTAMP
);

CREATE TABLE IF NOT EXISTS prekeys (
    id SERIAL PRIMARY KEY,
    public_key_hash BYTEA NOT NULL REFERENCES public_keys(public_key_hash) ON DELETE CASCADE,
    key_id BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    upload_time TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (public_key_hash, key_id)
);
EOF
    fi
fi

echo "Database initialization scripts set up"