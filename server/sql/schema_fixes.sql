-- Schema fixes for the SecNet server database

-- Add missing columns to pending_messages table
ALTER TABLE pending_messages ADD COLUMN IF NOT EXISTS priority SMALLINT DEFAULT 1;

-- Fix topics table (add missing columns)
ALTER TABLE topics ADD COLUMN IF NOT EXISTS topic_type VARCHAR(20) DEFAULT 'Public';
ALTER TABLE topics ADD COLUMN IF NOT EXISTS max_subscribers INTEGER DEFAULT 100;
ALTER TABLE topics ADD COLUMN IF NOT EXISTS max_message_size INTEGER DEFAULT 10485760;
ALTER TABLE topics ADD COLUMN IF NOT EXISTS requires_auth BOOLEAN DEFAULT FALSE;
ALTER TABLE topics ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;

-- Add missing capabilities column to topic_subscriptions
ALTER TABLE topic_subscriptions ADD COLUMN IF NOT EXISTS capabilities SMALLINT DEFAULT 1;

-- Add delivery_time to message_delivery
ALTER TABLE message_delivery ADD COLUMN IF NOT EXISTS delivery_time TIMESTAMP;

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

-- Enable the 'bigdecimal' feature for NUMERIC type support
-- Note: This will be handled in Cargo.toml modifications