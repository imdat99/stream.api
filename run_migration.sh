#!/bin/bash

# Migration runner script for stream.api
# Usage: ./run_migration.sh [migration_file.sql]

set -e

# Load environment variables from config if exists
if [ -f "config.yaml" ]; then
    echo "Loading configuration from config.yaml..."
fi

# Database connection parameters (adjust these based on your config)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-stream}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Stream API Migration Runner ===${NC}"

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo -e "${RED}Error: psql command not found. Please install PostgreSQL client.${NC}"
    exit 1
fi

# Build connection string
export PGPASSWORD="$DB_PASSWORD"

# Run specific migration or all migrations
if [ -n "$1" ]; then
    MIGRATION_FILE="$1"
    if [ ! -f "$MIGRATION_FILE" ]; then
        echo -e "${RED}Error: Migration file '$MIGRATION_FILE' not found${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Running migration: $MIGRATION_FILE${NC}"
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$MIGRATION_FILE"
    echo -e "${GREEN}✓ Migration completed successfully${NC}"
else
    # Run all migrations in order
    echo -e "${YELLOW}Running all migrations in ./migrations/...${NC}"
    for migration in $(ls -1 migrations/*.sql 2>/dev/null | sort); do
        echo -e "${YELLOW}Running: $migration${NC}"
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$migration"
        echo -e "${GREEN}✓ Completed: $migration${NC}"
        echo ""
    done
    echo -e "${GREEN}=== All migrations completed ===${NC}"
fi

unset PGPASSWORD
