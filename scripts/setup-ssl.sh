#!/bin/bash
set -e

echo "================================================"
echo "TruffleHog API - Let's Encrypt SSL Setup"
echo "================================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check if nginx is installed
if ! command -v nginx &> /dev/null; then
    echo "nginx is not installed. Please run setup-nginx.sh first."
    exit 1
fi

# Check if domain is provided
DOMAIN="truffle.betkido.com"
EMAIL="admin@betkido.com"

echo "Domain: $DOMAIN"
echo "Email: $EMAIL"
echo ""

read -p "Is this information correct? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please edit the script and update the domain and email."
    exit 1
fi

echo "[1/4] Stopping nginx temporarily..."
systemctl stop nginx

echo "[2/4] Obtaining SSL certificate..."
certbot certonly --standalone \
    -d $DOMAIN \
    --non-interactive \
    --agree-tos \
    --email $EMAIL \
    --preferred-challenges http

echo "[3/4] Starting nginx..."
systemctl start nginx

echo "[4/4] Setting up automatic renewal..."
# Certbot auto-renewal is already set up by default, but let's ensure it
systemctl enable certbot.timer
systemctl start certbot.timer

# Test renewal
certbot renew --dry-run

echo ""
echo "================================================"
echo "SSL certificate obtained successfully!"
echo "================================================"
echo ""
echo "Certificate location: /etc/letsencrypt/live/$DOMAIN/"
echo "Auto-renewal: Enabled (certbot.timer)"
echo ""
echo "Test the setup:"
echo "  https://$DOMAIN/health"
echo "  https://$DOMAIN/swagger/"
echo ""
echo "Check SSL rating:"
echo "  https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo ""

