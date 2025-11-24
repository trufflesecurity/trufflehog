#!/bin/bash
set -e

echo "================================================"
echo "TruffleHog API - nginx Setup Script"
echo "================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "[1/7] Installing nginx..."
apt-get update
apt-get install -y nginx

echo "[2/7] Installing certbot..."
apt-get install -y certbot python3-certbot-nginx

echo "[3/7] Creating certbot directory..."
mkdir -p /var/www/certbot

echo "[4/7] Copying nginx configuration..."
cp configs/nginx/truffle.betkido.com.conf /etc/nginx/sites-available/truffle.betkido.com.conf

echo "[5/7] Creating symbolic link..."
ln -sf /etc/nginx/sites-available/truffle.betkido.com.conf /etc/nginx/sites-enabled/

echo "[6/7] Removing default nginx site..."
rm -f /etc/nginx/sites-enabled/default

echo "[7/7] Testing nginx configuration..."
nginx -t

echo ""
echo "================================================"
echo "nginx configuration complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. Make sure DNS for truffle.betkido.com points to this server"
echo "2. Start the TruffleHog API server (docker-compose up -d)"
echo "3. Reload nginx: sudo systemctl reload nginx"
echo "4. Obtain SSL certificate: sudo ./scripts/setup-ssl.sh"
echo ""

