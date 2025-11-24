# TruffleHog REST API 🔍

A production-ready REST API for TruffleHog secret scanning with JWT authentication, async job processing, and comprehensive API documentation.

## Features

- ✅ **REST API** with Swagger/OpenAPI documentation  
- ✅ **JWT Authentication** with username/password  
- ✅ **851+ Detectors** including custom AI service detectors:
  - Exa AI, FireCrawl, Perplexity, OpenRouter
  - Google Gemini, Google Veo, HeyGen
  - MidJourney, Runway ML
  - + 842 built-in detectors
- ✅ **Async Job Processing** with Redis queue  
- ✅ **PostgreSQL** for persistent storage  
- ✅ **Docker Support** with docker-compose  
- ✅ **Webhook Notifications** for scan events  
- ✅ **Rate Limiting** and security headers  
- ✅ **HTTPS Support** with Let's Encrypt  

## Quick Start with Docker

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/trufflehog.git
cd trufflehog

# Copy environment file
cp .env.example .env
# Edit .env with your settings

# Start all services
docker-compose up -d

# Check services
docker-compose ps

# View logs
docker-compose logs -f api
```

## API Endpoints

### Authentication

**Login:**
```bash
curl -X POST https://truffle.betkido.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

**Register:**
```bash
curl -X POST https://truffle.betkido.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"newuser","password":"securepass","email":"user@example.com"}'
```

### Scanning (Protected - Requires JWT)

**Create Scan:**
```bash
curl -X POST https://truffle.betkido.com/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "repo_url": "https://github.com/user/repo",
    "branch": "main",
    "only_verified": true
  }'
```

**Get Scan Status:**
```bash
curl https://truffle.betkido.com/api/v1/scan/JOB_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Public Endpoints

- **Health Check:** `GET /health`
- **List Detectors:** `GET /api/v1/detectors`
- **Swagger UI:** `GET /swagger/`

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│   Nginx     │────▶│   API Server │────▶│ PostgreSQL │
│ (SSL/HTTPS) │     │  (Port 8080) │     │            │
└─────────────┘     └──────────────┘     └────────────┘
                           │
                           ▼
                    ┌────────────┐     ┌────────────┐
                    │   Redis    │────▶│  Workers   │
                    │   Queue    │     │  (Scans)   │
                    └────────────┘     └────────────┘
```

## Configuration

### Environment Variables

See `.env.example` for all available options.

**Important:** Change default passwords and JWT secret in production!

### Database Schema

The database schema is automatically initialized on first startup. Tables include:

- `users` - User accounts
- `scan_jobs` - Scan job metadata
- `scan_results` - Detected secrets
- `webhook_configs` - Webhook configurations
- `api_keys` - API key management

## Development

```bash
# Install dependencies
go mod download

# Run locally (requires PostgreSQL and Redis)
export POSTGRES_HOST=localhost
export REDIS_HOST=localhost
export JWT_SECRET=your-secret-here
go run cmd/api/main.go

# Generate Swagger docs
swag init -g cmd/api/main.go --output docs

# Run tests
go test ./...
```

## Production Deployment

1. **Set up domain and SSL:**
```bash
# Configure Nginx (see configs/nginx/)
sudo cp configs/nginx/truffle.betkido.com.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/truffle.betkido.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Get SSL certificate
sudo certbot certonly --nginx -d truffle.betkido.com
```

2. **Deploy with Docker:**
```bash
docker-compose up -d
```

3. **Monitor:**
```bash
docker-compose logs -f
docker-compose ps
```

## Security

- ✅ JWT tokens expire after 24 hours
- ✅ Passwords hashed with bcrypt
- ✅ Rate limiting enabled (100 req/min)
- ✅ HTTPS with Let's Encrypt
- ✅ Security headers configured
- ✅ CORS enabled with restrictions

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

⚠️ **IMPORTANT:** Change the default admin password immediately after first login!

## Integration Example (GitScout)

```javascript
const TruffleHogAPI = require('./trufflehog-client');

const client = new TruffleHogAPI({
  baseURL: 'https://truffle.betkido.com',
  username: 'your-username',
  password: 'your-password'
});

// Login
await client.login();

// Scan repository
const job = await client.createScan({
  repo_url: 'https://github.com/user/repo',
  only_verified: true
});

// Check status
const status = await client.getScanStatus(job.job_id);
console.log('Secrets found:', status.secrets_found);
```

## Troubleshooting

**API not responding:**
```bash
docker-compose logs api
sudo systemctl status trufflehog-api
```

**Database connection issues:**
```bash
docker-compose exec postgres psql -U trufflehog -d trufflehog -c "\dt"
```

**Redis connection issues:**
```bash
docker-compose exec redis redis-cli ping
```

## API Documentation

Interactive API documentation available at:
- **Swagger UI:** https://truffle.betkido.com/swagger/
- **OpenAPI Spec:** https://truffle.betkido.com/swagger/doc.json

## License

Apache 2.0 - See LICENSE file

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Submit pull request

## Support

- GitHub Issues: https://github.com/trufflesecurity/trufflehog/issues
- Documentation: https://truffle.betkido.com/swagger/

---

**Built with ❤️ using TruffleHog by TruffleSecurity**

