#!/bin/bash
set -e

echo "===== Master Build Script for SecNet Server ====="

# 1. Clean up first
./cleanup-sqlx.sh

# 2. Set up SQLx offline mode
./setup-sqlx-offline.sh

# 3. Build the Docker image
echo "Building Docker image..."
docker-compose build server

echo "===== Build Complete ====="
echo "You can now run the server with: docker-compose up -d"