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

# IMPORTANT FIX: Copy the binary with the correct name (server not secnet-server)
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

# Expose the port the server listens on
EXPOSE 8080

# IMPORTANT FIX: Run the binary with the correct name
CMD ["/usr/local/bin/server"]