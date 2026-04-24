#!/bin/bash
set -e

# Colors for better visibility
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}--- Starting FTI Stack ---${NC}"
echo -e "${BLUE}Analysis will run automatically in the Docker container before the backend starts.${NC}"

# Spin up everything. The 'intake' service will run analysis in its entrypoint.
docker compose up --build
