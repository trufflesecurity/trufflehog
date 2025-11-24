package handlers

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/db"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/queue"
	"github.com/trufflesecurity/trufflehog/v3/pkg/version"
)

type HealthHandler struct {
	database *db.Database
	queue    *queue.RedisQueue
}

func NewHealthHandler(database *db.Database, queue *queue.RedisQueue) *HealthHandler {
	return &HealthHandler{
		database: database,
		queue:    queue,
	}
}

// Health godoc
// @Summary      Health check
// @Description  Check the health status of the API and its dependencies
// @Tags         system
// @Produce      json
// @Success      200 {object} models.HealthResponse
// @Router       /health [get]
func (h *HealthHandler) Health(c *fiber.Ctx) error {
	services := make(map[string]string)

	// Check database
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := h.database.DB.PingContext(ctx); err != nil {
		services["database"] = "unhealthy: " + err.Error()
	} else {
		services["database"] = "healthy"
	}

	// Check Redis
	if _, err := h.queue.GetQueueLength(ctx, queue.ScanJobQueue); err != nil {
		services["redis"] = "unhealthy: " + err.Error()
	} else {
		services["redis"] = "healthy"
	}

	// Determine overall status
	status := "healthy"
	for _, svc := range services {
		if svc != "healthy" {
			status = "degraded"
			break
		}
	}

	return c.JSON(models.HealthResponse{
		Status:   status,
		Version:  version.BuildVersion,
		Services: services,
	})
}

