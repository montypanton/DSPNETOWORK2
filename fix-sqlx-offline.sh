#!/bin/bash
set -e

echo "Fixing SQLx offline mode for server builds..."

# Create proper sqlx-data.json file
cat > server/sqlx-data.json << EOF
{
  "db": "PostgreSQL",
  "25b41ef8be763090f3b1cc2c8eee1310ace9c1543b1a7b9a1efa9ebb6d340f17": {
    "describe": {
      "columns": [],
      "nullable": [],
      "parameters": {
        "Left": [
          "Bytea",
          "Bytea",
          "Bytea",
          "Bytea",
          "Float8",
          "Int2"
        ]
      }
    },
    "query": "INSERT INTO pending_messages (id, recipient_key_hash, encrypted_content, hmac, created_at, expiry, is_delivered, priority, delivery_attempts) VALUES ($1, $2, $3, $4, NOW(), to_timestamp($5), FALSE, $6, 0)"
  }
}
EOF

# Create a new Dockerfile with SQLX_OFFLINE=true
cat > Dockerfile.new << EOF
# Build stage
FROM rust:latest as builder

WORKDIR /usr/src/secnet

# Copy the entire server directory including all source files and dependencies
COPY server/ ./server/

# Install build dependencies 
RUN apt-get update && apt-get install -y \\
    pkg-config \\
    libssl-dev \\
    gcc \\
    libc6-dev \\
    && rm -rf /var/lib/apt/lists/*

# Force SQLx to use offline mode
ENV SQLX_OFFLINE=true

# Build the server binary with debug info for better error messages
WORKDIR /usr/src/secnet/server
RUN cargo build --release && \\
    ls -la target/release/

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies including postgresql client for debugging
RUN apt-get update && apt-get install -y \\
    ca-certificates \\
    libssl3 \\
    wget \\
    postgresql-client \\
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the server
RUN groupadd -r secnet && useradd -r -g secnet secnet

# Copy the binary and SQL scripts
COPY --from=builder /usr/src/secnet/server/target/release/secnet-server /usr/local/bin/secnet-server
COPY server/sql /usr/local/share/secnet/sql

# Set appropriate permissions
RUN chmod +x /usr/local/bin/secnet-server && \\
    chown -R secnet:secnet /usr/local/share/secnet

# Create a custom startup script for debugging
RUN echo '#!/bin/bash' > /usr/local/bin/start-server.sh && \\
    echo 'set -e' >> /usr/local/bin/start-server.sh && \\
    echo 'echo "Starting SecNet Server in debug mode"' >> /usr/local/bin/start-server.sh && \\
    echo 'echo "Environment variables:"' >> /usr/local/bin/start-server.sh && \\
    echo 'env | sort' >> /usr/local/bin/start-server.sh && \\
    echo 'echo "Testing database connection:"' >> /usr/local/bin/start-server.sh && \\
    echo 'PGPASSWORD=secnetpassword psql -h db -U secnetuser -d secnet -c "SELECT 1" || echo "Database connection failed"' >> /usr/local/bin/start-server.sh && \\
    echo 'echo "Starting server..."' >> /usr/local/bin/start-server.sh && \\
    echo 'exec /usr/local/bin/secnet-server' >> /usr/local/bin/start-server.sh && \\
    chmod +x /usr/local/bin/start-server.sh

# Switch to non-root user
USER secnet

# Set environment variables
ENV RUST_LOG=debug
ENV SERVER_PORT=8080
ENV DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet
ENV SQLX_OFFLINE=true

# Expose the port the server listens on
EXPOSE 8080

# Use the startup script instead of directly running the binary
CMD ["/usr/local/bin/start-server.sh"]
EOF

# Replace the old Dockerfile with the new one
mv Dockerfile.new Dockerfile

# Update .env file to use offline mode
cat > server/.env << EOF
DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet
SERVER_PORT=8080
RUST_LOG=info
SQLX_OFFLINE=true
EOF

# Ensure .cargo/config.toml exists and enforces offline mode
mkdir -p server/.cargo
cat > server/.cargo/config.toml << EOF
[env]
SQLX_OFFLINE = "true"
EOF

# Ensure SQLx offline mode is enforced in Cargo.toml
# Using a temporary file since macOS sed behaves differently
if ! grep -q 'sqlx.*features.*=.*\[.*"offline"' server/Cargo.toml; then
    echo "Adding offline feature to SQLx..."
    
    # Create a backup of the original file
    cp server/Cargo.toml server/Cargo.toml.bak
    
    # Add offline feature - this approach works on macOS
    awk '
    /sqlx.*=.*{.*features.*=.*\[/ {
        if (!index($0, "\"offline\"")) {
            # Add offline feature if not already present
            sub(/features.*=.*\[/, "&\"offline\", ")
        }
    }
    { print }
    ' server/Cargo.toml.bak > server/Cargo.toml
    
    # Remove backup if successful
    if [ $? -eq 0 ]; then
        rm server/Cargo.toml.bak
    else
        # Restore original in case of error
        mv server/Cargo.toml.bak server/Cargo.toml
        echo "Warning: Failed to update Cargo.toml"
    fi
fi

echo "SQLx offline mode fixed successfully"