package handlers

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/db"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/queue"
)

type ScanHandler struct {
	database *db.Database
	queue    *queue.RedisQueue
}

func NewScanHandler(database *db.Database, queue *queue.RedisQueue) *ScanHandler {
	return &ScanHandler{
		database: database,
		queue:    queue,
	}
}

// CreateScan godoc
// @Summary      Create a new scan job
// @Description  Initiate a new repository scan
// @Tags         scans
// @Accept       json
// @Produce      json
// @Param        request body models.ScanRequest true "Scan configuration"
// @Success      202 {object} models.ScanJobResponse
// @Failure      400 {object} models.ErrorResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/scan [post]
func (h *ScanHandler) CreateScan(c *fiber.Ctx) error {
	var req models.ScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid JSON body",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate repo URL
	if req.RepoURL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "validation_error",
			Message: "repo_url is required",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Create options map
	options := req.Options
	if options == nil {
		options = make(map[string]interface{})
	}
	options["branch"] = req.Branch
	options["since_commit"] = req.SinceCommit
	options["max_depth"] = req.MaxDepth
	options["no_verification"] = req.NoVerification
	options["only_verified"] = req.OnlyVerified

	// Create scan job in database
	job, err := h.database.CreateScanJob(req.RepoURL, options, nil)
	if err != nil {
		c.Context().Logger().Printf("ERROR: Failed to create scan job: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: fmt.Sprintf("Failed to create scan job: %v", err),
			Code:    fiber.StatusInternalServerError,
		})
	}

	// Enqueue job
	jobMsg := &queue.JobMessage{
		JobID:     job.ID,
		RepoURL:   req.RepoURL,
		Options:   options,
		CreatedAt: time.Now(),
	}

	ctx := context.Background()
	if err := h.queue.EnqueueScanJob(ctx, jobMsg); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to enqueue scan job",
			Code:    fiber.StatusInternalServerError,
		})
	}

	// Set initial status in Redis
	h.queue.SetJobStatus(ctx, job.ID, "queued", 24*time.Hour)

	return c.Status(fiber.StatusAccepted).JSON(models.ScanJobResponse{
		JobID:   job.ID.String(),
		Status:  "queued",
		Message: "Scan job created successfully",
	})
}

// GetScanStatus godoc
// @Summary      Get scan job status
// @Description  Retrieve the status and results of a scan job
// @Tags         scans
// @Produce      json
// @Param        jobId path string true "Job ID"
// @Param        page query int false "Page number" default(1)
// @Param        per_page query int false "Results per page" default(50)
// @Success      200 {object} models.ScanJobStatusResponse
// @Failure      404 {object} models.ErrorResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/scan/{jobId} [get]
func (h *ScanHandler) GetScanStatus(c *fiber.Ctx) error {
	jobIDStr := c.Params("jobId")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_job_id",
			Message: "Invalid job ID format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Get job from database
	job, err := h.database.GetScanJob(jobID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to retrieve scan job",
			Code:    fiber.StatusInternalServerError,
		})
	}

	if job == nil {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "not_found",
			Message: "Scan job not found",
			Code:    fiber.StatusNotFound,
		})
	}

	// Parse pagination parameters
	page, _ := strconv.Atoi(c.Query("page", "1"))
	perPage, _ := strconv.Atoi(c.Query("per_page", "50"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	offset := (page - 1) * perPage

	// Get results if scan is completed
	var results []*models.ScanResult
	var total int
	var pageInfo *models.PageInfo

	if job.Status == "completed" || job.Status == "failed" {
		results, total, err = h.database.GetScanResults(jobID, perPage, offset)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
				Error:   "internal_error",
				Message: "Failed to retrieve scan results",
				Code:    fiber.StatusInternalServerError,
			})
		}

		totalPages := (total + perPage - 1) / perPage
		pageInfo = &models.PageInfo{
			Total:      total,
			Page:       page,
			PerPage:    perPage,
			TotalPages: totalPages,
		}

		// Redact secrets in response (only show redacted version)
		for _, result := range results {
			result.Secret = ""
		}
	}

	return c.JSON(models.ScanJobStatusResponse{
		Job:     job,
		Results: results,
		Page:    pageInfo,
	})
}

// CancelScan godoc
// @Summary      Cancel a scan job
// @Description  Cancel a running or queued scan job
// @Tags         scans
// @Produce      json
// @Param        jobId path string true "Job ID"
// @Success      200 {object} models.SuccessResponse
// @Failure      404 {object} models.ErrorResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/scan/{jobId} [delete]
func (h *ScanHandler) CancelScan(c *fiber.Ctx) error {
	jobIDStr := c.Params("jobId")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_job_id",
			Message: "Invalid job ID format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Get job from database
	job, err := h.database.GetScanJob(jobID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to retrieve scan job",
			Code:    fiber.StatusInternalServerError,
		})
	}

	if job == nil {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "not_found",
			Message: "Scan job not found",
			Code:    fiber.StatusNotFound,
		})
	}

	// Can only cancel queued or running jobs
	if job.Status != "queued" && job.Status != "running" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_status",
			Message: "Can only cancel queued or running jobs",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Update status to cancelled
	cancelMsg := "Cancelled by user"
	if err := h.database.UpdateScanJobStatus(jobID, "cancelled", job.Progress, &cancelMsg); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to cancel scan job",
			Code:    fiber.StatusInternalServerError,
		})
	}

	ctx := context.Background()
	h.queue.SetJobStatus(ctx, jobID, "cancelled", 24*time.Hour)

	return c.JSON(models.SuccessResponse{
		Success: true,
		Message: "Scan job cancelled successfully",
	})
}

