# Use the latest Rust image to ensure compatibility with your Cargo.lock version
FROM rust:latest as builder

WORKDIR /usr/src/secnet
COPY . .

# Install build dependencies 
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build the server binary - ensure it builds as secnet-server
RUN cd server && \
    cargo build --release

# Debug: List the release directory to check what binary name was actually produced
RUN ls -la server/target/release/

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder with the correct name secnet-server
COPY --from=builder /usr/src/secnet/server/target/release/secnet-server /usr/local/bin/secnet-server

# Verify the binary exists and is executable in the final image
RUN ls -la /usr/local/bin/ && \
    chmod +x /usr/local/bin/secnet-server

# Create a non-root user to run the server
RUN groupadd -r secnet && useradd -r -g secnet secnet
USER secnet

# Set environment variables
ENV RUST_LOG=info
ENV SERVER_PORT=8080
ENV DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet

# Expose the port the server listens on
EXPOSE 8080

# Run the server using the correct binary name
CMD ["/usr/local/bin/secnet-server"]