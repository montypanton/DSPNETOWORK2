#!/bin/bash
set -e

echo "SecNet Database Fix Script"
echo "=========================="
echo "This script will apply schema fixes to the SecNet server database"
echo

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "ERROR: docker-compose is not installed or not in PATH!"
    exit 1
fi

# Check if .env file exists to get database connection details
if [ ! -f "server/.env" ]; then
    echo "ERROR: server/.env file not found! Cannot connect to database."
    exit 1
fi

# Source database info from .env
source server/.env
echo "Using database: $DATABASE_URL"

# Check if database container is running
DB_CONTAINER=$(docker-compose ps -q db)
if [ -z "$DB_CONTAINER" ]; then
    echo "ERROR: Database container is not running. Start it with 'docker-compose up -d db'"
    exit 1
fi

echo "Applying database schema fixes..."

# Copy the schema fixes SQL file to the container
docker cp server/sql/schema_fixes.sql ${DB_CONTAINER}:/tmp/schema_fixes.sql

# Execute the SQL file inside the container
docker exec -i ${DB_CONTAINER} psql -U secnetuser -d secnet -f /tmp/schema_fixes.sql

echo "Database schema fixes applied successfully!"
echo
echo "Next steps:"
echo "1. Update server/Cargo.toml to add the 'bigdecimal' feature to sqlx"
echo "2. Rebuild the server with 'docker-compose build server'"
echo "3. Restart the server with 'docker-compose up -d'"
echo