#!/bin/bash
set -e

echo "Generating SQLx metadata for offline mode..."

# Ensure the database is up
docker-compose up -d db

# Wait for database to be ready
attempt=0
while [ $attempt -lt 30 ]; do
    if docker-compose exec db pg_isready -U secnetuser -d secnet; then
        echo "Database is ready!"
        break
    fi
    echo "Waiting for database to initialize... (attempt $((attempt+1))/30)"
    sleep 5
    attempt=$((attempt+1))
done

if [ $attempt -eq 30 ]; then
    echo "ERROR: Database failed to initialize in time"
    exit 1
fi

# Generate SQLx data
echo "Running sqlx prepare..."
cd server
cargo sqlx prepare --database-url postgresql://secnetuser:secnetpassword@localhost:5432/secnet

echo "SQLx metadata generated successfully"