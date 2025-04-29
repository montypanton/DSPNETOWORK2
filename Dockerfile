FROM rust:latest as builder

WORKDIR /usr/src/secnet
COPY . .

# Show directory contents for debugging
RUN ls -la && ls -la server && ls -la server/src

# Remove the lib section from Cargo.toml to avoid the lib.rs requirement
RUN sed -i '/\[lib\]/,/^$/d' server/Cargo.toml

# Build only the binary
RUN cd server && cargo build --release --bin secnet-server -v

FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /usr/src/secnet/server/target/release/secnet-server /usr/local/bin/secnet-server

# Create a non-root user to run the server
RUN groupadd -r secnet && useradd -r -g secnet secnet
USER secnet

# Set environment variables
ENV RUST_LOG=info
ENV SERVER_PORT=8080
ENV DATABASE_URL=postgres://secnetuser:secnetpassword@db:5432/secnet

# Expose the port the server listens on
EXPOSE 8080

# Run the server
CMD ["secnet-server"]