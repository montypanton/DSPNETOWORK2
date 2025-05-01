#!/bin/bash
set -e

echo "===== Comprehensive SQLx Setup for Offline Mode ====="

# 1. Start the database container if it's not already running
echo "Ensuring database is running..."
docker-compose up -d db

# 2. Wait for database to be ready (important!)
echo "Waiting for database to be fully initialized..."
for i in {1..30}; do
  if docker-compose exec db pg_isready -U secnetuser -d secnet -h localhost > /dev/null 2>&1; then
    echo "Database is ready!"
    break
  fi
  echo "Waiting for database to be ready... ($i/30)"
  sleep 2
  if [ $i -eq 30 ]; then
    echo "ERROR: Database did not become ready in time"
    exit 1
  fi
done

# 3. Apply database schema fixes
echo "Applying database schema fixes..."
docker-compose exec db psql -U secnetuser -d secnet -f /docker-entrypoint-initdb.d/init.sql

# 4. Create a temporary .env file with the correct DATABASE_URL for local development
echo "Setting up environment for SQLx..."
cat > server/.env << EOF
DATABASE_URL=postgres://secnetuser:secnetpassword@localhost:5432/secnet
SERVER_PORT=8080
RUST_LOG=info
EOF

# 5. Install SQLx CLI if needed
echo "Checking for SQLx CLI..."
if ! command -v sqlx &> /dev/null; then
  echo "Installing SQLx CLI..."
  cargo install sqlx-cli --no-default-features --features postgres
fi

# 6. Generate the sqlx-data.json file (the crucial part)
echo "Generating sqlx-data.json file..."
cd server
cargo sqlx prepare --merged -- --all-features
cd ..

# 7. Create config for offline mode
echo "Setting up offline mode configuration..."
mkdir -p server/.cargo
cat > server/.cargo/config.toml << EOF
[env]
SQLX_OFFLINE = "true"
EOF

echo "===== SQLx Offline Mode Setup Complete ====="
echo "You can now build the project with: docker-compose build server"