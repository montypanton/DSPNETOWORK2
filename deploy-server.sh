#!/bin/bash
set -e

echo "===== SecNet Server Full Deployment Workflow ====="

# Step 1: Build the server container
echo "Step 1: Building the server..."
./build-server.sh

# Step 2: Start the database only
echo "Step 2: Starting the database..."
docker-compose up -d db

# Step 3: Wait for database to be ready
echo "Step 3: Waiting for database to be ready..."
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
    echo "Check database logs with: docker-compose logs db"
    exit 1
fi

# Step 4: Generate SQLx metadata (if not using offline mode)
echo "Step 4: Do you want to generate SQLx metadata from the database? (y/N)"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    # Temporarily create a directory for SQLx metadata
    mkdir -p server/.sqlx
    
    # Get the current working directory
    CWD=$(pwd)
    
    # Go to the server directory
    cd server
    
    # Export the database URL
    export DATABASE_URL="postgres://secnetuser:secnetpassword@localhost:5432/secnet"
    
    # Install sqlx-cli if not already installed
    if ! command -v sqlx &> /dev/null; then
        echo "Installing sqlx-cli..."
        cargo install sqlx-cli --no-default-features --features postgres
    fi
    
    # Run the prepare command
    echo "Generating SQLx metadata..."
    cargo sqlx prepare --merged
    
    # Return to the original directory
    cd "$CWD"
    
    # Turn off offline mode for the initial run
    docker-compose stop server
    docker-compose rm -f server
    docker-compose build --build-arg SQLX_OFFLINE=false server
else
    echo "Skipping SQLx metadata generation, using offline mode"
fi

# Step 5: Start the full stack
echo "Step 5: Starting the full server stack..."
docker-compose up -d

# Step 6: Verify server started correctly
echo "Step 6: Verifying server status..."
attempt=0
while [ $attempt -lt 12 ]; do
    if curl -s http://localhost:8080/api/connection/ping | grep -q "Pong"; then
        echo "Server is up and running!"
        break
    fi
    echo "Waiting for server to start... (attempt $((attempt+1))/12)"
    sleep 10
    attempt=$((attempt+1))
done

if [ $attempt -eq 12 ]; then
    echo "WARNING: Could not verify server is running"
    echo "Check server logs with: docker-compose logs server"
else
    echo "===== SecNet Server Deployed Successfully ====="
    echo "Server is running at: http://localhost:8080"
fi

echo "You can use the following commands to manage the server:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop server: docker-compose down"
echo "  - Restart server: docker-compose restart"