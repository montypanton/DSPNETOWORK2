-- Complete schema fixes for SecNet server database

-- Add missing columns to pending_messages table
ALTER TABLE pending_messages ADD COLUMN IF NOT EXISTS hmac BYTEA;
ALTER TABLE pending_messages ADD COLUMN IF NOT EXISTS priority SMALLINT DEFAULT 1;
ALTER TABLE pending_messages ADD COLUMN IF NOT EXISTS delivery_attempts SMALLINT DEFAULT 0;
ALTER TABLE pending_messages ADD COLUMN IF NOT EXISTS metadata_obfuscation BYTEA;

-- Add missing column to public_keys
ALTER TABLE public_keys ADD COLUMN IF NOT EXISTS connection_count INTEGER DEFAULT 1;
ALTER TABLE public_keys ADD COLUMN IF NOT EXISTS last_ip_hash BYTEA;

-- Add missing column to prekeys
ALTER TABLE prekeys ADD COLUMN IF NOT EXISTS upload_time TIMESTAMP DEFAULT NOW();
ALTER TABLE prekeys ADD COLUMN IF NOT EXISTS is_used BOOLEAN DEFAULT FALSE;

-- Fix topic_subscriptions table
ALTER TABLE topic_subscriptions ADD COLUMN IF NOT EXISTS join_time TIMESTAMP DEFAULT NOW();
ALTER TABLE topic_subscriptions ADD COLUMN IF NOT EXISTS last_active TIMESTAMP DEFAULT NOW();
ALTER TABLE topic_subscriptions ADD COLUMN IF NOT EXISTS capabilities SMALLINT DEFAULT 1;

-- Add missing columns to topic_messages
ALTER TABLE topic_messages ADD COLUMN IF NOT EXISTS hmac BYTEA;
ALTER TABLE topic_messages ADD COLUMN IF NOT EXISTS metadata BYTEA;

-- Add missing columns to topics table
ALTER TABLE topics ADD COLUMN IF NOT EXISTS topic_type VARCHAR(20) DEFAULT 'Public';
ALTER TABLE topics ADD COLUMN IF NOT EXISTS max_subscribers INTEGER DEFAULT 100;
ALTER TABLE topics ADD COLUMN IF NOT EXISTS max_message_size INTEGER DEFAULT 10485760; -- 10MB default
ALTER TABLE topics ADD COLUMN IF NOT EXISTS requires_auth BOOLEAN DEFAULT FALSE;
ALTER TABLE topics ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;

-- Create topic_invitations table if it doesn't exist
CREATE TABLE IF NOT EXISTS topic_invitations (
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

-- Add missing column to message_delivery
ALTER TABLE message_delivery ADD COLUMN IF NOT EXISTS delivery_time TIMESTAMP;

-- Create other missing tables if needed
CREATE TABLE IF NOT EXISTS pending_messages (
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
) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS public_keys (
    public_key_hash BYTEA PRIMARY KEY,
    ed25519_public_key BYTEA NOT NULL,
    x25519_public_key BYTEA NOT NULL,
    kyber_public_key BYTEA NOT NULL,
    connection_token UUID NOT NULL,
    last_active TIMESTAMP NOT NULL DEFAULT NOW(),
    registration_time TIMESTAMP NOT NULL DEFAULT NOW(),
    connection_count INTEGER NOT NULL DEFAULT 1,
    last_ip_hash BYTEA -- Hashed IP address for abuse prevention
) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS topic_messages (
    id BYTEA PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    encrypted_content BYTEA NOT NULL,
    hmac BYTEA NOT NULL, -- Integrity protection
    posted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expiry TIMESTAMP NOT NULL,
    metadata BYTEA -- Optional encrypted metadata
) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS topics (
    id BYTEA PRIMARY KEY,
    topic_type VARCHAR(20) NOT NULL DEFAULT 'Public', -- Public, Private, Ephemeral
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP, -- NULL means never expires
    max_subscribers INTEGER NOT NULL DEFAULT 100,
    max_message_size INTEGER NOT NULL DEFAULT 10485760, -- 10MB default
    requires_auth BOOLEAN NOT NULL DEFAULT FALSE
) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS topic_subscriptions (
    id SERIAL PRIMARY KEY,
    topic_id BYTEA NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    subscriber_token BYTEA NOT NULL, -- Blinded token (cannot be linked to public_key_hash)
    routing_data BYTEA NOT NULL, -- Encrypted routing information
    capabilities SMALLINT NOT NULL DEFAULT 1, -- 1: read, 2: write, 4: admin
    join_time TIMESTAMP NOT NULL DEFAULT NOW(),
    last_active TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (topic_id, subscriber_token)
) ON CONFLICT DO NOTHING;