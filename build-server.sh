#!/bin/bash
set -e

echo "===== SecNet Server Build Script ====="
echo "This script will build the SecNet server container"

# Function for error handling
handle_error() {
    echo "ERROR: Build failed at step $1"
    echo "See error messages above for details"
    exit 1
}

# Step 1: Setup SQLx offline mode
echo "Step 1: Setting up SQLx offline mode..."
./setup-sqlx-offline.sh || handle_error "SQLx setup"

# Step 2: Setup database initialization scripts
echo "Step 2: Setting up database initialization scripts..."
./setup-db-scripts.sh || handle_error "Database script setup"

# Step 3: Check Cargo.toml to ensure binary name is correct
echo "Step 3: Verifying Cargo.toml configuration..."
if [ -f server/Cargo.toml ]; then
    # Check if [[bin]] section exists and has the correct name
    if ! grep -q '^\[\[bin\]\]' server/Cargo.toml; then
        echo "Adding [[bin]] section to Cargo.toml..."
        cat >> server/Cargo.toml << EOF

[[bin]]
name = "secnet-server"
path = "src/main.rs"
EOF
    elif ! grep -A5 '^\[\[bin\]\]' server/Cargo.toml | grep -q 'name.*=.*"secnet-server"'; then
        echo "Updating binary name in Cargo.toml..."
        sed -i 's/name.*=.*".*"/name = "secnet-server"/' server/Cargo.toml
    fi
    
    # Ensure sqlx features are configured correctly
    if ! grep -q 'sqlx.*=.*{.*version.*=.*"0.6' server/Cargo.toml; then
        echo "ERROR: sqlx dependency not found in Cargo.toml. Manual update required."
        exit 1
    elif ! grep -q 'sqlx.*=.*{.*version.*=.*"0.6.*features.*=.*\[.*"bigdecimal"' server/Cargo.toml; then
        echo "Adding bigdecimal feature to sqlx in Cargo.toml..."
        sed -i 's/sqlx.*=.*{.*version.*=.*"0.6.*features.*=.*\[/&"bigdecimal", /' server/Cargo.toml
    fi
else
    echo "ERROR: server/Cargo.toml not found!"
    exit 1
fi

# Step 4: Build the Docker images
echo "Step 4: Building Docker images..."
docker-compose build || handle_error "Docker build"

echo "===== Build Completed Successfully ====="
echo "You can now start the server with: docker-compose up -d"
echo "Access the server at: http://localhost:8080"