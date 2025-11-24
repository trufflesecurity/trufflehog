# TruffleHog REST API

A production-ready REST API for TruffleHog secret scanning service with async job processing, webhook notifications, and comprehensive secret detection including custom AI service detectors.

## Features

- ✅ **Async Repository Scanning** - Non-blocking Git repository scans with job status tracking
- ✅ **1000+ Secret Detectors** - Includes custom AI service detectors (Exa AI, FireCrawl, Perplexity, OpenRouter, Google Gemini, Runway ML, Google Veo, HeyGen, MidJourney)
- ✅ **Webhook Notifications** - Real-time notifications for scan events with HMAC signatures
- ✅ **Swagger Documentation** - Interactive API documentation at `/swagger/`
- ✅ **PostgreSQL Storage** - Persistent storage for scan results and job metadata
- ✅ **Redis Queue** - Scalable async job processing with worker pools
- ✅ **nginx Reverse Proxy** - Production-ready setup with Let's Encrypt SSL
- ✅ **Rate Limiting** - Built-in API rate limiting and security headers
- ✅ **Health Monitoring** - Health check endpoints for service monitoring

## Quick Start

### Prerequisites

- Go 1.24+
- Docker & Docker Compose
- nginx (for production)
- Domain name pointing to your server (for SSL)

### Development Setup

1. **Clone and setup**
```bash
cd /root/trufflehog
make install-deps
```

2. **Start dependencies**
```bash
make docker-up
```

3. **Run API server**
```bash
make run
```

4. **Test the API**
```bash
# Health check
curl http://localhost:8080/health

# List detectors
curl http://localhost:8080/api/v1/detectors

# Swagger UI
open http://localhost:8080/swagger/
```

### Production Deployment

1. **Deploy the API**
```bash
sudo make deploy
```

2. **Update environment variables**
```bash
sudo nano /opt/trufflehog/.env
# Change all passwords and secrets
sudo systemctl restart trufflehog-api
```

3. **Setup nginx**
```bash
sudo make setup-nginx
```

4. **Setup SSL with Let's Encrypt**
```bash
sudo make setup-ssl
```

5. **Verify deployment**
```bash
curl https://truffle.betkido.com/health
curl https://truffle.betkido.com/swagger/
```

## API Endpoints

### Scan Management

**POST /api/v1/scan** - Create a new scan job
```bash
curl -X POST https://truffle.betkido.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/user/repo",
    "branch": "main",
    "no_verification": false
  }'
```

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Scan job created successfully"
}
```

**GET /api/v1/scan/{jobId}** - Get scan status and results
```bash
curl https://truffle.betkido.com/api/v1/scan/550e8400-e29b-41d4-a716-446655440000
```

**DELETE /api/v1/scan/{jobId}** - Cancel a scan job
```bash
curl -X DELETE https://truffle.betkido.com/api/v1/scan/550e8400-e29b-41d4-a716-446655440000
```

### Detectors

**GET /api/v1/detectors** - List all available detectors
```bash
curl https://truffle.betkido.com/api/v1/detectors
```

### Webhooks

**POST /api/v1/webhooks** - Register a webhook
```bash
curl -X POST https://truffle.betkido.com/api/v1/webhooks \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-webhook-endpoint.com/hook",
    "secret": "your-webhook-secret-min-16-chars",
    "events": ["scan.completed", "scan.failed"],
    "retry_count": 3,
    "timeout_seconds": 30
  }'
```

**GET /api/v1/webhooks** - List webhooks

**GET /api/v1/webhooks/{webhookId}** - Get webhook details

**PUT /api/v1/webhooks/{webhookId}** - Update webhook

**DELETE /api/v1/webhooks/{webhookId}** - Delete webhook

### System

**GET /health** - Health check
```bash
curl https://truffle.betkido.com/health
```

## Webhook Events

The API sends webhook notifications for the following events:

- `scan.started` - Scan job has started processing
- `scan.completed` - Scan job completed successfully
- `scan.failed` - Scan job failed with error

### Webhook Payload Example

```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "repo_url": "https://github.com/user/repo",
  "status": "completed",
  "chunks_scanned": 1250,
  "bytes_scanned": 5242880,
  "secrets_found": 3,
  "verified_secrets": 2,
  "unverified_secrets": 1
}
```

### Webhook Signature Verification

Webhooks include an HMAC-SHA256 signature in the `X-Webhook-Signature` header:

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)
```

## Configuration

### Environment Variables

```bash
# API Server
API_PORT=8080
API_HOST=0.0.0.0
API_WORKERS=4

# Database
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=trufflehog
POSTGRES_USER=trufflehog
POSTGRES_PASSWORD=your_secure_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# Security
API_SECRET_KEY=your_api_secret_key
WEBHOOK_SIGNING_KEY=your_webhook_signing_key

# Limits
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=3600
RATE_LIMIT_PER_MINUTE=100
```

## Architecture

```
┌─────────────┐
│   nginx     │ ← SSL Termination, Rate Limiting
│   (443)     │
└──────┬──────┘
       │
┌──────▼──────┐
│  Fiber API  │ ← HTTP Server (Port 8080)
│   Server    │
└──────┬──────┘
       │
   ┌───┴───┬──────────┬──────────┐
   │       │          │          │
┌──▼───┐ ┌─▼──────┐ ┌▼────────┐ ┌▼────────┐
│ PG   │ │ Redis  │ │ Workers │ │Webhooks │
│ DB   │ │ Queue  │ │  Pool   │ │ Manager │
└──────┘ └────────┘ └─────────┘ └─────────┘
```

## Service Management

```bash
# Check status
sudo systemctl status trufflehog-api

# Start service
sudo systemctl start trufflehog-api

# Stop service
sudo systemctl stop trufflehog-api

# Restart service
sudo systemctl restart trufflehog-api

# View logs
sudo journalctl -u trufflehog-api -f

# Enable on boot
sudo systemctl enable trufflehog-api
```

## Makefile Commands

```bash
make help              # Show all available commands
make build             # Build the API server
make run               # Run the API server locally
make test              # Run unit tests
make test-integration  # Run integration tests
make docker-up         # Start Docker containers
make docker-down       # Stop Docker containers
make deploy            # Deploy to production
make setup-nginx       # Setup nginx reverse proxy
make setup-ssl         # Setup Let's Encrypt SSL
make clean             # Clean build artifacts
make dev               # Start development environment
make status            # Check service status
make logs              # View service logs
```

## Security Considerations

1. **HTTPS Only** - Always use HTTPS in production
2. **API Keys** - Implement API key authentication for production use
3. **Rate Limiting** - Configured at 100 requests/minute per IP
4. **Webhook Signatures** - Verify HMAC signatures on webhook payloads
5. **Environment Variables** - Never commit secrets to version control
6. **Firewall** - Only expose ports 80 and 443
7. **Database Credentials** - Use strong, unique passwords
8. **Regular Updates** - Keep dependencies and OS updated

## Monitoring

### Health Check

```bash
curl https://truffle.betkido.com/health
```

Response:
```json
{
  "status": "healthy",
  "version": "3.0.0",
  "services": {
    "database": "healthy",
    "redis": "healthy"
  }
}
```

### Metrics

Prometheus metrics available at `/metrics` (if enabled)

## Troubleshooting

### API server won't start
```bash
# Check logs
sudo journalctl -u trufflehog-api -n 50

# Check if port 8080 is available
sudo netstat -tulpn | grep 8080

# Check database connection
docker exec trufflehog-postgres pg_isready
```

### Database connection errors
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# View PostgreSQL logs
docker logs trufflehog-postgres

# Restart PostgreSQL
docker-compose restart postgres
```

### Redis connection errors
```bash
# Check Redis is running
docker ps | grep redis

# Test Redis connection
docker exec trufflehog-redis redis-cli ping
```

### Scans not processing
```bash
# Check worker status in logs
sudo journalctl -u trufflehog-api -f | grep Worker

# Check Redis queue length
docker exec trufflehog-redis redis-cli LLEN scan_jobs
```

## Performance Tuning

### Scale Workers

Edit `/opt/trufflehog/.env`:
```bash
API_WORKERS=8
MAX_CONCURRENT_SCANS=10
```

### Database Connection Pool

Edit `pkg/api/db/db.go`:
```go
db.SetMaxOpenConns(50)
db.SetMaxIdleConns(10)
```

### Redis Connection Pool

Configure in `pkg/api/queue/redis.go` as needed.

## Custom Detectors

The API includes 9 custom AI service detectors:

1. **Exa AI** - AI search API keys
2. **FireCrawl** - Web scraping API keys  
3. **Perplexity** - AI chat API keys
4. **OpenRouter** - LLM routing API keys
5. **Google Gemini** - Google AI API keys
6. **Runway ML** - AI video generation keys
7. **Google Veo** - Google video AI keys
8. **HeyGen** - AI avatar generation keys
9. **MidJourney** - AI art generation tokens

All detectors support verification where APIs are available.

## License

Apache 2.0

## Support

- GitHub Issues: https://github.com/trufflesecurity/trufflehog/issues
- Email: support@trufflesecurity.com
- Documentation: https://truffle.betkido.com/swagger/

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

