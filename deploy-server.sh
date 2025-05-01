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

# Step 4: Start the full stack
echo "Step 4: Starting the full server stack..."
docker-compose up -d

# Step 5: Verify server started correctly
echo "Step 5: Verifying server status..."
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