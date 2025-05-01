#!/bin/bash
set -e

echo "===== SecNet Server Build Fix ====="
echo "This script will fix the SQLx database connection issues during build"

# Step 1: Create a directory for SQLx metadata if it doesn't exist
mkdir -p server/.sqlx

# Step 2: Create or update the .env file to ensure proper database credentials
cat > server/.env << EOF
DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet
SERVER_PORT=8080
RUST_LOG=info
SQLX_OFFLINE=true
EOF

# Step 3: Create a cargo config to force offline mode
mkdir -p server/.cargo
cat > server/.cargo/config.toml << EOF
[env]
SQLX_OFFLINE = "true"
EOF

# Step 4: Update the Dockerfile to use the offline mode
cat > Dockerfile << EOF
# Build stage
FROM rust:latest as builder

WORKDIR /usr/src/secnet
COPY . .

# Install build dependencies 
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Set SQLx to offline mode
ENV SQLX_OFFLINE=true

# Build the server binary
WORKDIR /usr/src/secnet/server
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the server
RUN groupadd -r secnet && useradd -r -g secnet secnet

# IMPORTANT FIX: Copy the binary with the correct name
COPY --from=builder /usr/src/secnet/server/target/release/secnet-server /usr/local/bin/server

# Set appropriate permissions
RUN chmod +x /usr/local/bin/server && \
    chown secnet:secnet /usr/local/bin/server

# Switch to non-root user
USER secnet

# Set environment variables
ENV RUST_LOG=info
ENV SERVER_PORT=8080
ENV DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet
ENV SQLX_OFFLINE=true

# Expose the port the server listens on
EXPOSE 8080

# Run the binary with the correct name
CMD ["/usr/local/bin/server"]
EOF

# Step 5: Create a JSON SQLx-data file with prepared queries
cat > server/sqlx-data.json << EOF
{
  "db": "PostgreSQL",
  "1a2b3c4d5e6f7g8h": {
    "describe": {
      "columns": [],
      "nullable": [],
      "parameters": {
        "Left": []
      }
    },
    "query": "-- This is a placeholder for SQLx offline mode"
  }
}
EOF

# Step 6: Update the build-offline.sh script
cat > server/build-offline.sh << EOF
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
EOF
chmod +x server/build-offline.sh

# Step 7: Update the docker-compose.yml file to ensure database is ready before server starts
cat > docker-compose.yml << EOF
services:
  server:
    build:
      context: .
      dockerfile: Dockerfile  
    platform: linux/amd64
    ports:
      - "8080:8080"
    depends_on:
      db:
        condition: service_healthy
    environment:
      - DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet
      - SERVER_PORT=8080
      - RUST_LOG=info
      - SQLX_OFFLINE=true
    restart: unless-stopped
    networks:
      - secnet-network
    volumes:
      - server-data:/var/lib/secnet
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/api/connection/ping"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s

  db:
    image: postgres:14
    platform: linux/amd64
    environment:
      - POSTGRES_USER=secnetuser
      - POSTGRES_PASSWORD=secnetpassword
      - POSTGRES_DB=secnet
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./server/sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    networks:
      - secnet-network
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U secnetuser -d secnet"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres-data:
  server-data:

networks:
  secnet-network:
    driver: bridge
EOF

# Final instructions
echo ""
echo "===== BUILD FIX COMPLETED ====="
echo "The script has set up SQLx in offline mode to fix the database connection issues during build."
echo ""
echo "To build the server container, run:"
echo "    docker-compose build server"
echo ""
echo "To start the entire system, run:"
echo "    docker-compose up -d"
echo ""
echo "NOTE: For proper offline mode to work with your real SQL queries, you should:"
echo "1. Start the database container: docker-compose up -d db"
echo "2. Wait for it to initialize: sleep 15"
echo "3. Run the fix-database.sh script to apply schema fixes"
echo "4. Run the prepare-sqlx.sh script to generate proper query metadata"
echo "5. Then build and run the server container"