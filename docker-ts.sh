#!/bin/bash
# Docker troubleshooting script for SecNet project
set -e

echo "===== SecNet Docker Troubleshooting ====="
echo "This script will help diagnose issues with the Docker setup."

# Check Docker and Docker Compose installation
echo -e "\n1. Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH!"
else
    echo "Docker is installed: $(docker --version)"
fi

if ! command -v docker-compose &> /dev/null; then
    echo "ERROR: Docker Compose is not installed or not in PATH!"
else
    echo "Docker Compose is installed: $(docker-compose --version)"
fi

# Check if containers are running
echo -e "\n2. Checking container status..."
docker ps -a | grep -E 'secnet|db'

# Check the binary name in Cargo.toml
echo -e "\n3. Checking binary name in Cargo.toml..."
if [ -f "server/Cargo.toml" ]; then
    echo "Cargo.toml exists."
    BIN_NAME=$(grep -A 10 '^\[\[bin\]\]' server/Cargo.toml | grep 'name' | head -1 | sed 's/.*"\(.*\)".*/\1/')
    if [ -n "$BIN_NAME" ]; then
        echo "Binary name defined in Cargo.toml: $BIN_NAME"
    else
        echo "WARNING: No binary name found in [[bin]] section!"
        PACKAGE_NAME=$(grep -m 1 'name' server/Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
        echo "Package name (likely default binary name): $PACKAGE_NAME"
    fi
else
    echo "ERROR: server/Cargo.toml not found!"
fi

# Check if binary exists in target directory
echo -e "\n4. Checking compiled binary..."
if [ -d "server/target/release" ]; then
    echo "Release directory exists. Contents:"
    ls -la server/target/release/
    
    if [ -n "$BIN_NAME" ] && [ -f "server/target/release/$BIN_NAME" ]; then
        echo "Binary $BIN_NAME exists and has size: $(du -h server/target/release/$BIN_NAME | cut -f1)"
        file server/target/release/$BIN_NAME
    else
        echo "WARNING: Expected binary not found or binary name couldn't be determined!"
    fi
else
    echo "ERROR: Release directory not found. Have you built the project?"
fi

# Check Docker image for binary
echo -e "\n5. Checking Docker image..."
IMAGE_ID=$(docker images | grep secnet-server | awk '{print $3}')
if [ -n "$IMAGE_ID" ]; then
    echo "SecNet server image found: $IMAGE_ID"
    echo "Running test command in image to check binary..."
    docker run --rm --entrypoint sh $IMAGE_ID -c "ls -la /usr/local/bin && file /usr/local/bin/* 2>/dev/null || echo 'No binaries found'"
else
    echo "ERROR: SecNet server image not found. Have you built it with docker-compose build?"
fi

# Check logs for running containers
echo -e "\n6. Checking container logs (if running)..."
if docker ps | grep -q secnet; then
    echo "Server container logs:"
    docker logs $(docker ps | grep secnet | awk '{print $1}') | tail -20
else
    echo "Server container is not running."
fi

if docker ps | grep -q db; then
    echo "Database container logs:"
    docker logs $(docker ps | grep db | awk '{print $1}') | tail -10
else
    echo "Database container is not running."
fi

echo -e "\n===== Troubleshooting Suggestions ====="
echo "1. Make sure the binary name in Dockerfile CMD matches the name in Cargo.toml"
echo "2. If you get 'exec format error', the binary architecture doesn't match the container"
echo "   Try explicitly setting platform in docker-compose.yml: platform: linux/amd64"
echo "3. Check that all required environment variables are set correctly"
echo "4. Ensure the database container is fully started before the server container"

echo -e "\nTo apply fixes:"
echo "1. Rebuild the Docker image: docker-compose build --no-cache"
echo "2. Restart containers: docker-compose down && docker-compose up -d"
echo "3. Check logs again: docker-compose logs -f"