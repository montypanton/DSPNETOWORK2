# Build stage
FROM rust:latest as builder

WORKDIR /usr/src/secnet

# Copy the sqlx-data.json first to make build caching more effective
COPY server/sqlx-data.json server/sqlx-data.json
COPY server/Cargo.toml server/Cargo.toml
COPY server/Cargo.lock server/Cargo.lock

# Create dummy src/lib.rs to allow cargo to cache dependencies
RUN mkdir -p server/src && \
    echo "fn main() {}" > server/src/main.rs && \
    echo "pub fn dummy() {}" > server/src/lib.rs && \
    cd server && \
    SQLX_OFFLINE=true cargo build --release && \
    rm -rf src/

# Now copy the real source files
COPY server/src server/src
COPY server/sql server/sql
COPY server/.cargo server/.cargo

# Install build dependencies 
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Force SQLx to use offline mode
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
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to run the server
RUN groupadd -r secnet && useradd -r -g secnet secnet

# Copy the binary with the correct name
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