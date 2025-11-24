package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/db"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
)

type WebhookHandler struct {
	database *db.Database
}

func NewWebhookHandler(database *db.Database) *WebhookHandler {
	return &WebhookHandler{
		database: database,
	}
}

// CreateWebhook godoc
// @Summary      Create a webhook
// @Description  Register a new webhook for scan events
// @Tags         webhooks
// @Accept       json
// @Produce      json
// @Param        request body models.WebhookCreateRequest true "Webhook configuration"
// @Success      201 {object} models.WebhookConfig
// @Failure      400 {object} models.ErrorResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/webhooks [post]
func (h *WebhookHandler) CreateWebhook(c *fiber.Ctx) error {
	var req models.WebhookCreateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid JSON body",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Validate required fields
	if req.URL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "validation_error",
			Message: "url is required",
			Code:    fiber.StatusBadRequest,
		})
	}

	if req.Secret == "" || len(req.Secret) < 16 {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "validation_error",
			Message: "secret is required and must be at least 16 characters",
			Code:    fiber.StatusBadRequest,
		})
	}

	if len(req.Events) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "validation_error",
			Message: "at least one event is required",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Set defaults
	if req.RetryCount == 0 {
		req.RetryCount = 3
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 30
	}

	// Create webhook
	webhook := &models.WebhookConfig{
		URL:            req.URL,
		Secret:         req.Secret,
		Events:         req.Events,
		IsActive:       true,
		RetryCount:     req.RetryCount,
		TimeoutSeconds: req.TimeoutSeconds,
		Headers:        req.Headers,
	}

	if err := h.database.CreateWebhook(webhook); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to create webhook",
			Code:    fiber.StatusInternalServerError,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(webhook)
}

// ListWebhooks godoc
// @Summary      List webhooks
// @Description  Get all registered webhooks
// @Tags         webhooks
// @Produce      json
// @Success      200 {object} models.WebhookListResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/webhooks [get]
func (h *WebhookHandler) ListWebhooks(c *fiber.Ctx) error {
	webhooks, err := h.database.ListWebhooks(nil)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to retrieve webhooks",
			Code:    fiber.StatusInternalServerError,
		})
	}

	return c.JSON(models.WebhookListResponse{
		Webhooks: webhooks,
		Total:    len(webhooks),
	})
}

// GetWebhook godoc
// @Summary      Get webhook
// @Description  Get a specific webhook by ID
// @Tags         webhooks
// @Produce      json
// @Param        webhookId path string true "Webhook ID"
// @Success      200 {object} models.WebhookConfig
// @Failure      404 {object} models.ErrorResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/webhooks/{webhookId} [get]
func (h *WebhookHandler) GetWebhook(c *fiber.Ctx) error {
	webhookIDStr := c.Params("webhookId")
	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_webhook_id",
			Message: "Invalid webhook ID format",
			Code:    fiber.StatusBadRequest,
		})
	}

	webhook, err := h.database.GetWebhook(webhookID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to retrieve webhook",
			Code:    fiber.StatusInternalServerError,
		})
	}

	if webhook == nil {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "not_found",
			Message: "Webhook not found",
			Code:    fiber.StatusNotFound,
		})
	}

	return c.JSON(webhook)
}

// UpdateWebhook godoc
// @Summary      Update webhook
// @Description  Update an existing webhook
// @Tags         webhooks
// @Accept       json
// @Produce      json
// @Param        webhookId path string true "Webhook ID"
// @Param        request body models.WebhookUpdateRequest true "Webhook updates"
// @Success      200 {object} models.WebhookConfig
// @Failure      400 {object} models.ErrorResponse
// @Failure      404 {object} models.ErrorResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/webhooks/{webhookId} [put]
func (h *WebhookHandler) UpdateWebhook(c *fiber.Ctx) error {
	webhookIDStr := c.Params("webhookId")
	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_webhook_id",
			Message: "Invalid webhook ID format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Check if webhook exists
	webhook, err := h.database.GetWebhook(webhookID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to retrieve webhook",
			Code:    fiber.StatusInternalServerError,
		})
	}

	if webhook == nil {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "not_found",
			Message: "Webhook not found",
			Code:    fiber.StatusNotFound,
		})
	}

	var req models.WebhookUpdateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid JSON body",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Apply updates
	if req.URL != "" {
		webhook.URL = req.URL
	}
	if req.Secret != "" {
		webhook.Secret = req.Secret
	}
	if len(req.Events) > 0 {
		webhook.Events = req.Events
	}
	if req.IsActive != nil {
		webhook.IsActive = *req.IsActive
	}

	// Update in database
	if err := h.database.UpdateWebhook(webhookID, webhook.URL, webhook.Secret, webhook.Events, webhook.IsActive); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to update webhook",
			Code:    fiber.StatusInternalServerError,
		})
	}

	// Get updated webhook
	updatedWebhook, _ := h.database.GetWebhook(webhookID)
	return c.JSON(updatedWebhook)
}

// DeleteWebhook godoc
// @Summary      Delete webhook
// @Description  Delete a webhook
// @Tags         webhooks
// @Produce      json
// @Param        webhookId path string true "Webhook ID"
// @Success      200 {object} models.SuccessResponse
// @Failure      404 {object} models.ErrorResponse
// @Failure      500 {object} models.ErrorResponse
// @Router       /api/v1/webhooks/{webhookId} [delete]
func (h *WebhookHandler) DeleteWebhook(c *fiber.Ctx) error {
	webhookIDStr := c.Params("webhookId")
	webhookID, err := uuid.Parse(webhookIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ErrorResponse{
			Error:   "invalid_webhook_id",
			Message: "Invalid webhook ID format",
			Code:    fiber.StatusBadRequest,
		})
	}

	// Check if webhook exists
	webhook, err := h.database.GetWebhook(webhookID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to retrieve webhook",
			Code:    fiber.StatusInternalServerError,
		})
	}

	if webhook == nil {
		return c.Status(fiber.StatusNotFound).JSON(models.ErrorResponse{
			Error:   "not_found",
			Message: "Webhook not found",
			Code:    fiber.StatusNotFound,
		})
	}

	if err := h.database.DeleteWebhook(webhookID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(models.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to delete webhook",
			Code:    fiber.StatusInternalServerError,
		})
	}

	return c.JSON(models.SuccessResponse{
		Success: true,
		Message: "Webhook deleted successfully",
	})
}

