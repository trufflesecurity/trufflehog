#!/bin/bash
set -e

echo "================================================"
echo "TruffleHog API - Production Deployment Script"
echo "================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

INSTALL_DIR="/opt/trufflehog"
SERVICE_USER="trufflehog"

echo "[1/12] Creating service user..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    echo "User $SERVICE_USER created"
else
    echo "User $SERVICE_USER already exists"
fi

echo "[2/12] Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/logs"

echo "[3/12] Copying TruffleHog CLI binary..."
if [ -f "/usr/local/bin/trufflehog" ]; then
    cp /usr/local/bin/trufflehog "$INSTALL_DIR/trufflehog"
    echo "Using existing trufflehog binary from /usr/local/bin"
elif [ -f "/usr/bin/trufflehog" ]; then
    cp /usr/bin/trufflehog "$INSTALL_DIR/trufflehog"
    echo "Using existing trufflehog binary from /usr/bin"
else
    echo "Warning: No trufflehog binary found. Please install it first."
    echo "Visit: https://github.com/trufflesecurity/trufflehog#installation"
    exit 1
fi

echo "[4/12] Building API server..."
cd /root/trufflehog
CGO_ENABLED=0 go build -o "$INSTALL_DIR/trufflehog-api" ./cmd/api

echo "[5/12] Copying documentation..."
cp -r docs "$INSTALL_DIR/"

echo "[6/12] Creating environment file..."
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cat > "$INSTALL_DIR/.env" << 'EOF'
# API Server Configuration
API_PORT=8080
API_HOST=0.0.0.0
API_WORKERS=4

# Database Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=trufflehog
POSTGRES_USER=trufflehog
POSTGRES_PASSWORD=CHANGE_THIS_PASSWORD

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=CHANGE_THIS_PASSWORD

# Security
API_SECRET_KEY=CHANGE_THIS_SECRET_KEY
WEBHOOK_SIGNING_KEY=CHANGE_THIS_WEBHOOK_KEY

# Limits
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=3600
RATE_LIMIT_PER_MINUTE=100
EOF
    echo "Environment file created at $INSTALL_DIR/.env"
    echo "IMPORTANT: Edit $INSTALL_DIR/.env and change all passwords and secrets!"
else
    echo "Environment file already exists"
fi

echo "[7/12] Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 640 "$INSTALL_DIR/.env"
chmod 755 "$INSTALL_DIR/trufflehog"
chmod 755 "$INSTALL_DIR/trufflehog-api"

echo "[8/12] Installing systemd service..."
cp configs/systemd/trufflehog-api.service /etc/systemd/system/
systemctl daemon-reload

echo "[9/12] Enabling service..."
systemctl enable trufflehog-api.service

echo "[10/12] Starting Docker containers..."
# Use docker compose (v2) instead of docker-compose (v1)
cd "$REPO_DIR" && docker compose up -d

echo "[11/12] Waiting for database..."
sleep 5

echo "[12/12] Running database migrations..."
docker exec -i trufflehog-postgres psql -U trufflehog -d trufflehog < pkg/api/db/migrations/001_initial_schema.sql || true

echo "[13/13] Starting API service..."
systemctl start trufflehog-api.service

echo ""
echo "================================================"
echo "Deployment Complete!"
echo "================================================"
echo ""
echo "Installation directory: $INSTALL_DIR"
echo "Service user: $SERVICE_USER"
echo ""
echo "IMPORTANT NEXT STEPS:"
echo "1. Edit $INSTALL_DIR/.env and update all passwords/secrets"
echo "2. Restart service: sudo systemctl restart trufflehog-api"
echo "3. Setup nginx: sudo ./scripts/setup-nginx.sh"
echo "4. Setup SSL: sudo ./scripts/setup-ssl.sh"
echo ""
echo "Service management:"
echo "  Status:  sudo systemctl status trufflehog-api"
echo "  Start:   sudo systemctl start trufflehog-api"
echo "  Stop:    sudo systemctl stop trufflehog-api"
echo "  Restart: sudo systemctl restart trufflehog-api"
echo "  Logs:    sudo journalctl -u trufflehog-api -f"
echo ""
echo "Test the API:"
echo "  curl http://localhost:8080/health"
echo ""

