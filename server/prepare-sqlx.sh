#!/bin/bash
set -e

echo "Preparing SQLx for offline mode..."

# Make sure .env file exists
if [ ! -f .env ]; then
    echo "Error: .env file not found!"
    exit 1
fi

# Read DATABASE_URL from .env
export $(grep -v '^#' .env | xargs)

if [ -z "$DATABASE_URL" ]; then
    echo "Error: DATABASE_URL not found in .env file!"
    exit 1
fi

echo "Using DATABASE_URL: $DATABASE_URL"

# Install sqlx-cli if not already installed
if ! command -v sqlx &> /dev/null; then
    echo "Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features postgres
fi

# Run prepare command to create sqlx-data.json
echo "Generating sqlx-data.json..."
cargo sqlx prepare --merged -- --lib

echo "SQLx preparation complete!"
echo "You can now build the project in offline mode without needing a database connection."