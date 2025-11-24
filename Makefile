.PHONY: help build run test deploy clean docker-up docker-down swagger

help: ## Display this help message
	@echo "TruffleHog REST API - Available Commands"
	@echo "========================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the API server
	@echo "Building API server..."
	CGO_ENABLED=0 go build -o bin/trufflehog-api ./cmd/api
	@echo "Build complete: bin/trufflehog-api"

run: ## Run the API server locally
	@echo "Starting API server..."
	go run ./cmd/api/main.go

test: ## Run tests
	@echo "Running tests..."
	go test -v ./pkg/api/...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	./scripts/test-api.sh

docker-up: ## Start Docker containers (PostgreSQL, Redis)
	@echo "Starting Docker containers..."
	docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Running database migrations..."
	@docker exec -i trufflehog-postgres psql -U trufflehog -d trufflehog < pkg/api/db/migrations/001_initial_schema.sql || true
	@echo "Docker containers are ready!"

docker-down: ## Stop Docker containers
	@echo "Stopping Docker containers..."
	docker-compose down

docker-logs: ## View Docker container logs
	docker-compose logs -f

swagger: ## Generate Swagger documentation
	@echo "Generating Swagger docs..."
	@go install github.com/swaggo/swag/cmd/swag@latest
	swag init -g pkg/api/server.go -o docs

deploy: ## Deploy to production (requires root)
	@echo "Deploying to production..."
	@sudo ./scripts/deploy.sh

setup-nginx: ## Setup nginx reverse proxy (requires root)
	@echo "Setting up nginx..."
	@sudo ./scripts/setup-nginx.sh

setup-ssl: ## Setup Let's Encrypt SSL (requires root)
	@echo "Setting up SSL..."
	@sudo ./scripts/setup-ssl.sh

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/
	rm -rf docs/swagger.*

install-deps: ## Install Go dependencies
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

dev: docker-up build run ## Start development environment

status: ## Check service status
	@systemctl status trufflehog-api || echo "Service not installed"

logs: ## View service logs
	@journalctl -u trufflehog-api -f

.DEFAULT_GOAL := help
