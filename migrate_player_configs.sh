#!/bin/bash

# Full migration script for player_configs feature
# This script:
#   1. Runs the SQL migration to create player_configs table
#   2. Migrates data from user_preferences to player_configs
#   3. Removes player-related columns from user_preferences
#   4. Regenerates Go models to reflect schema changes
#
# Usage: ./migrate_player_configs.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Database config from config.yaml or environment
DB_HOST="${DB_HOST:-47.84.63.130}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-video_db}"
DB_USER="${DB_USER:-postgres}"
DB_PASSWORD="${DB_PASSWORD:-D@tkhong9}"

export PGPASSWORD="$DB_PASSWORD"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Player Configs Migration Script${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Step 1: Run SQL migration
echo -e "${YELLOW}[Step 1/3] Running SQL migration...${NC}"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f full_player_configs_migration.sql

if [ $? -ne 0 ]; then
    echo -e "${RED}SQL migration failed!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ SQL migration completed${NC}"
echo ""

# Step 2: Regenerate Go models
echo -e "${YELLOW}[Step 2/3] Regenerating Go models...${NC}"
go run cmd/gendb/main.go

if [ $? -ne 0 ]; then
    echo -e "${RED}Model generation failed!${NC}"
    echo -e "${YELLOW}Note: You may need to manually update the model files.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Go models regenerated${NC}"
echo ""

# Step 3: Build to verify
echo -e "${YELLOW}[Step 3/3] Building to verify changes...${NC}"
go build -o bin/api ./cmd/api

if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Build successful${NC}"
echo ""

unset PGPASSWORD

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Migration completed successfully!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${BLUE}Summary of changes:${NC}"
echo "  ✓ player_configs table created"
echo "  ✓ Data migrated from user_preferences"
echo "  ✓ Player columns removed from user_preferences:"
echo "    - autoplay, loop, muted"
echo "    - show_controls, pip, airplay, chromecast"
echo "    - encrytion_m3u8"
echo "  ✓ Go models regenerated"
echo ""
echo -e "${YELLOW}Note: Please restart your application to apply changes.${NC}"
