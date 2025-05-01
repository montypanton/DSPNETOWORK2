#!/bin/bash
set -e

echo "Building SecNet Server with SQLx offline mode"

# Set offline mode
export SQLX_OFFLINE=true

# Build the server
cd server
cargo build --release
cd ..

echo "Build completed successfully!"
