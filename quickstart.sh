#!/bin/bash

set -e

echo "Starting ScanLedger quickstart..."

# Generate TLS bundle
echo "Generating TLS certificates..."
bash generate-tls-bundle.sh

# Setup environment file
echo "Setting up environment file..."
cp .env.example .env

# Generate random tokens and passwords
echo "Generating secure credentials..."
POSTGRES_PASSWORD=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
ADMIN_TOKEN=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
TASKER_TOKEN=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)

# Update .env file with generated values
sed -i "s/POSTGRES_PASSWORD=changeme/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
sed -i "s/POSTGRES_HOST=localhost/POSTGRES_HOST=postgres/" .env
sed -i "s/ADMIN_TOKEN=changeme/ADMIN_TOKEN=$ADMIN_TOKEN/" .env
sed -i "s/TASKER_TOKEN=changeme/TASKER_TOKEN=$TASKER_TOKEN/" .env

# Start Docker containers
echo "Starting Docker containers..."
docker compose up -d

# Basic health check
echo "Checking ScanLedger availability..."
sleep 7

if curl -sk https://localhost/health >/dev/null 2>&1; then
  echo "ScanLedger is up and responding."
else
  echo "ScanLedger did not respond on https://localhost/health"
  echo "Check container logs if the problem persists."
fi

echo "Quickstart complete."

# Display admin token for convenience
echo ""
echo "========================================"
echo "Admin Token: $ADMIN_TOKEN"
echo "========================================"
echo ""
echo "Note: Store this token securely. You'll need it for API authentication."
