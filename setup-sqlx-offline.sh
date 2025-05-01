#!/bin/bash
set -e

echo "Setting up SQLx for offline mode..."

# Create necessary directories
mkdir -p server/.sqlx
mkdir -p server/.cargo

# Create or update the .env file
cat > server/.env << EOF
DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet
SERVER_PORT=8080
RUST_LOG=info
SQLX_OFFLINE=true
EOF

# Set up cargo config to force offline mode
cat > server/.cargo/config.toml << EOF
[env]
SQLX_OFFLINE = "true"
EOF

# Create a basic sqlx-data.json if it doesn't exist
if [ ! -f server/sqlx-data.json ]; then
    cat > server/sqlx-data.json << EOF
{
  "db": "PostgreSQL",
  "0123456789abcdef": {
    "describe": {
      "columns": [],
      "nullable": [],
      "parameters": {
        "Left": []
      }
    },
    "query": "-- This is a placeholder for SQLx offline mode"
  }
}
EOF
fi

echo "SQLx offline mode configuration completed"