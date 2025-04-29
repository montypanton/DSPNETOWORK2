# Use the latest Rust image to ensure compatibility with your Cargo.lock version
FROM rust:latest as builder

WORKDIR /usr/src/secnet
COPY . .

# Show directory contents for debugging
RUN ls -la && \
    ls -la server && \
    ls -la server/src

# Install build dependencies 
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Remove the lib section from Cargo.toml to avoid the lib.rs requirement
RUN sed -i '/\[lib\]/,/^$/d' server/Cargo.toml

# Build the binary
RUN cd server && \
    cargo build --release --bin secnet-server

# Verify the binary exists and is executable
RUN ls -la server/target/release && \
    file server/target/release/secnet-server && \
    chmod +x server/target/release/secnet-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder with explicit path
COPY --from=builder /usr/src/secnet/server/target/release/secnet-server /usr/local/bin/

# Verify the binary exists and is executable in the final image
RUN ls -la /usr/local/bin/secnet-server && \
    chmod +x /usr/local/bin/secnet-server && \
    which secnet-server

# Create a non-root user to run the server
RUN groupadd -r secnet && useradd -r -g secnet secnet
USER secnet

# Set environment variables
ENV RUST_LOG=info
ENV SERVER_PORT=8080
ENV DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet

# Expose the port the server listens on
EXPOSE 8080

# Run the server with absolute path to ensure it's found
CMD ["/usr/local/bin/secnet-server"]