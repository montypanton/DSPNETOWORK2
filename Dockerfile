# Build stage
FROM rust:latest as builder

WORKDIR /usr/src/secnet

# Copy the entire server directory including all source files and dependencies
COPY server/ ./server/

# Install build dependencies 
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Force SQLx to use offline mode
ENV SQLX_OFFLINE=true

# Build the server binary with debug info for better error messages
WORKDIR /usr/src/secnet/server
RUN cargo build --release && \
    ls -la target/release/

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies including postgresql client for debugging
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    wget \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the server
RUN groupadd -r secnet && useradd -r -g secnet secnet

# Copy the binary and SQL scripts
COPY --from=builder /usr/src/secnet/server/target/release/secnet-server /usr/local/bin/secnet-server
COPY server/sql /usr/local/share/secnet/sql

# Set appropriate permissions
RUN chmod +x /usr/local/bin/secnet-server && \
    chown -R secnet:secnet /usr/local/share/secnet

# Create a custom startup script for debugging
RUN echo '#!/bin/bash' > /usr/local/bin/start-server.sh && \
    echo 'set -e' >> /usr/local/bin/start-server.sh && \
    echo 'echo "Starting SecNet Server in debug mode"' >> /usr/local/bin/start-server.sh && \
    echo 'echo "Environment variables:"' >> /usr/local/bin/start-server.sh && \
    echo 'env | sort' >> /usr/local/bin/start-server.sh && \
    echo 'echo "Testing database connection:"' >> /usr/local/bin/start-server.sh && \
    echo 'PGPASSWORD=secnetpassword psql -h db -U secnetuser -d secnet -c "SELECT 1" || echo "Database connection failed"' >> /usr/local/bin/start-server.sh && \
    echo 'echo "Starting server..."' >> /usr/local/bin/start-server.sh && \
    echo 'exec /usr/local/bin/secnet-server' >> /usr/local/bin/start-server.sh && \
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