package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/trufflesecurity/trufflehog/v3/pkg/api"
)

func main() {
	log.Println("TruffleHog REST API Server")
	log.Println("========================================")

	// Create server
	server, err := api.NewServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		if err := server.Start(ctx); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-sigChan
	log.Println("Received shutdown signal...")

	// Cancel context
	cancel()

	// Shutdown server
	if err := server.Shutdown(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("Server stopped gracefully")
}

