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

# Check binary name in Cargo.toml
echo "Verifying binary names in Cargo.toml..."
BINARY_NAME=$(grep -A5 '^\[\[bin\]\]' server/Cargo.toml | grep 'name =' | head -1 | cut -d'"' -f2 || echo "server")
echo "Expected binary name from Cargo.toml: $BINARY_NAME"

# Build the server
echo "Building server..."
cd server
cargo build --release
cd ..

# Verify the binary exists
if [ -f "server/target/release/$BINARY_NAME" ]; then
  echo "Binary successfully built at: server/target/release/$BINARY_NAME"
else
  echo "ERROR: Binary not found at expected location!"
  echo "Checking for other binaries in the release directory:"
  ls -la server/target/release/
  exit 1
fi

# Build Docker containers with platform specification
echo "Building Docker containers..."
docker-compose build --no-cache

echo "Build completed successfully!"
echo "You can now run the server with: docker-compose up -d"
echo "And use the client with: ./target/release/secnet"