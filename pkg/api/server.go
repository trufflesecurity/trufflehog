package api

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/db"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/middleware"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/queue"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/webhooks"
	_ "github.com/trufflesecurity/trufflehog/v3/docs"
)

// @title TruffleHog REST API
// @version 1.0
// @description REST API for TruffleHog secret scanning service
// @termsOfService https://trufflesecurity.com/terms

// @contact.name API Support
// @contact.url https://trufflesecurity.com/support
// @contact.email support@trufflesecurity.com

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host truffle.betkido.com
// @BasePath /
// @schemes https http

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key

type Server struct {
	app         *fiber.App
	database    *db.Database
	queue       *queue.RedisQueue
	webhookMgr  *webhooks.WebhookManager
	workerPool  *queue.WorkerPool
	port        string
}

func NewServer() (*Server, error) {
	// Initialize database
	database, err := db.NewDatabase()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize Redis queue
	redisQueue, err := queue.NewRedisQueue()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Redis queue: %w", err)
	}

	// Initialize webhook manager
	webhookMgr := webhooks.NewWebhookManager(database)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "TruffleHog API v1.0",
		ServerHeader: "TruffleHog",
		ErrorHandler: customErrorHandler,
	})

	// Setup middleware
	middleware.SetupMiddleware(app)

	// Get port from environment
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	server := &Server{
		app:        app,
		database:   database,
		queue:      redisQueue,
		webhookMgr: webhookMgr,
		port:       port,
	}

	// Setup routes
	server.setupRoutes()

	// Initialize worker pool
	numWorkers := 4
	if val := os.Getenv("API_WORKERS"); val != "" {
		fmt.Sscanf(val, "%d", &numWorkers)
	}
	server.workerPool = queue.NewWorkerPool(numWorkers, redisQueue, database, webhookMgr)

	return server, nil
}

func (s *Server) setupRoutes() {
	// Health check
	healthHandler := handlers.NewHealthHandler(s.database, s.queue)
	s.app.Get("/health", healthHandler.Health)

	// API v1 routes
	api := s.app.Group("/api/v1")

	// Auth routes (public)
	authHandler := handlers.NewAuthHandler(s.database)
	api.Post("/auth/login", authHandler.Login)
	api.Post("/auth/register", authHandler.Register)

	// Protected routes (require JWT)
	protected := api.Group("/")
	protected.Use(middleware.JWTAuth)

	// Scan routes
	scanHandler := handlers.NewScanHandler(s.database, s.queue)
	protected.Post("/scan", scanHandler.CreateScan)
	protected.Get("/scan/:jobId", scanHandler.GetScanStatus)
	protected.Delete("/scan/:jobId", scanHandler.CancelScan)

	// Webhook routes
	webhookHandler := handlers.NewWebhookHandler(s.database)
	protected.Post("/webhooks", webhookHandler.CreateWebhook)
	protected.Get("/webhooks", webhookHandler.ListWebhooks)
	protected.Get("/webhooks/:webhookId", webhookHandler.GetWebhook)
	protected.Put("/webhooks/:webhookId", webhookHandler.UpdateWebhook)
	protected.Delete("/webhooks/:webhookId", webhookHandler.DeleteWebhook)

	// Detector routes (public)
	detectorHandler := handlers.NewDetectorHandler()
	api.Get("/detectors", detectorHandler.ListDetectors)

	// Swagger documentation
	s.app.Get("/swagger/*", swagger.HandlerDefault)

	// Root endpoint
	s.app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"name":    "TruffleHog REST API",
			"version": "1.0.0",
			"docs":    "/swagger/",
			"auth": fiber.Map{
				"login":    "/api/v1/auth/login",
				"register": "/api/v1/auth/register",
			},
		})
	})
}

func (s *Server) Start(ctx context.Context) error {
	// Start worker pool
	log.Printf("Starting worker pool...")
	s.workerPool.Start(ctx)

	// Start webhook retry worker
	log.Printf("Starting webhook retry worker...")
	go s.webhookMgr.StartRetryWorker(ctx)

	// Start HTTP server
	log.Printf("Starting API server on port %s...", s.port)
	log.Printf("Swagger UI available at http://localhost:%s/swagger/", s.port)
	
	return s.app.Listen(":" + s.port)
}

func (s *Server) Shutdown() error {
	log.Printf("Shutting down server...")

	// Stop worker pool
	s.workerPool.Stop()

	// Close connections
	if err := s.queue.Close(); err != nil {
		log.Printf("Error closing Redis: %v", err)
	}

	if err := s.database.Close(); err != nil {
		log.Printf("Error closing database: %v", err)
	}

	// Shutdown Fiber
	return s.app.Shutdown()
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error":   "request_error",
		"message": err.Error(),
		"code":    code,
	})
}

