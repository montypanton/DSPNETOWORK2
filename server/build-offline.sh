#!/bin/bash
set -e

echo "Building SecNet Server with SQLx offline mode"

# Step 1: Start the database and wait for it to be ready
echo "Starting PostgreSQL database..."
docker-compose up -d db
echo "Waiting for database to be ready..."
sleep 15

# Step 2: Apply database schema fixes
echo "Applying database schema fixes..."
bash fix-database.sh

# Step 3: Generate SQLx offline data
echo "Generating SQLx offline data..."
cd server
bash prepare-sqlx.sh
cd ..

# Step 4: Build the Docker image with SQLX_OFFLINE=true
echo "Building Docker images with offline mode..."
docker-compose build server

echo "Build completed successfully!"
echo "You can now run the server with: docker-compose up -d"