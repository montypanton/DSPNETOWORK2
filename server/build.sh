#!/bin/bash
set -e

echo "Building SecNet Project..."

# Clean up any previous build artifacts
echo "Cleaning up previous builds..."
if [ -d "server/target" ]; then
  rm -rf server/target
fi

# Make sure we have the latest dependencies
echo "Updating Rust..."
rustup update stable

# Build the server
echo "Building server..."
cd server
cargo build --release
cd ..

# Build the client
echo "Building client..."
cargo build --release

# Build Docker containers
echo "Building Docker containers..."
docker-compose build

echo "Build completed successfully!"
echo "You can now run the server with: docker-compose up -d"
echo "And use the client with: ./target/release/secnet"