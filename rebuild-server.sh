#!/bin/bash
set -e

echo "===== SecNet Server Rebuild Script ====="
echo "This script will completely rebuild the SecNet server with proper SQLx offline mode"

# Step 1: Fix SQLx offline mode
echo "Step 1: Fixing SQLx offline mode..."
./fix-sqlx-offline.sh

# Step 2: Stop and remove all existing containers
echo "Step 2: Stopping and removing existing containers..."
docker-compose down

# Step 3: Clean up Docker build cache
echo "Step 3: Cleaning Docker build cache..."
docker builder prune -f

# Step 4: Rebuild from scratch
echo "Step 4: Rebuilding containers from scratch..."
docker-compose build --no-cache

echo "===== Rebuild completed successfully ====="
echo "You can now start the server with: docker-compose up -d"