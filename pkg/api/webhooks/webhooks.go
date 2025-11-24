package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/db"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
)

type WebhookManager struct {
	database *db.Database
	client   *http.Client
}

func NewWebhookManager(database *db.Database) *WebhookManager {
	return &WebhookManager{
		database: database,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (wm *WebhookManager) TriggerEvent(ctx context.Context, event string, payload map[string]interface{}, jobID *uuid.UUID) {
	// Get all webhooks subscribed to this event
	webhooks, err := wm.database.GetActiveWebhooksForEvent(event)
	if err != nil {
		log.Printf("Failed to get webhooks for event %s: %v", event, err)
		return
	}

	// Create delivery for each webhook
	for _, webhook := range webhooks {
		delivery := &models.WebhookDelivery{
			WebhookID: webhook.ID,
			JobID:     jobID,
			Event:     event,
			Payload:   payload,
		}

		if err := wm.database.CreateWebhookDelivery(delivery); err != nil {
			log.Printf("Failed to create webhook delivery: %v", err)
			continue
		}

		// Try immediate delivery
		go wm.deliverWebhook(ctx, webhook, delivery)
	}
}

func (wm *WebhookManager) deliverWebhook(ctx context.Context, webhook *models.WebhookConfig, delivery *models.WebhookDelivery) {
	// Prepare payload
	payloadBytes, err := json.Marshal(delivery.Payload)
	if err != nil {
		log.Printf("Failed to marshal webhook payload: %v", err)
		return
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("Failed to create webhook request: %v", err)
		return
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TruffleHog-Webhook/1.0")
	req.Header.Set("X-Webhook-Event", delivery.Event)
	req.Header.Set("X-Webhook-Delivery", delivery.ID.String())

	// Add custom headers
	for key, value := range webhook.Headers {
		req.Header.Set(key, value)
	}

	// Generate signature
	signature := generateSignature(payloadBytes, webhook.Secret)
	req.Header.Set("X-Webhook-Signature", signature)

	// Send request
	resp, err := wm.client.Do(req)
	if err != nil {
		errMsg := err.Error()
		wm.database.UpdateWebhookDelivery(delivery.ID, 0, "", errMsg)
		
		// Schedule retry
		if delivery.RetryCount < webhook.RetryCount {
			wm.scheduleRetry(delivery, webhook)
		}
		return
	}
	defer resp.Body.Close()

	// Read response
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	responseBody := buf.String()

	// Update delivery status
	wm.database.UpdateWebhookDelivery(delivery.ID, resp.StatusCode, responseBody, "")

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("Webhook delivered successfully to %s", webhook.URL)
	} else {
		log.Printf("Webhook delivery failed with status %d", resp.StatusCode)
		
		// Schedule retry for non-2xx responses
		if delivery.RetryCount < webhook.RetryCount {
			wm.scheduleRetry(delivery, webhook)
		}
	}
}

func (wm *WebhookManager) scheduleRetry(delivery *models.WebhookDelivery, webhook *models.WebhookConfig) {
	// Exponential backoff: 1min, 5min, 15min
	delays := []time.Duration{1 * time.Minute, 5 * time.Minute, 15 * time.Minute}
	
	var delay time.Duration
	if delivery.RetryCount < len(delays) {
		delay = delays[delivery.RetryCount]
	} else {
		delay = 15 * time.Minute
	}

	nextRetry := time.Now().Add(delay)
	
	// Update delivery with next retry time
	// Note: This is simplified - production would need a proper retry queue
	log.Printf("Scheduling webhook retry for %s at %s", delivery.ID, nextRetry)
}

func generateSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifySignature(payload []byte, signature, secret string) bool {
	expectedSignature := generateSignature(payload, secret)
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

func (wm *WebhookManager) StartRetryWorker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wm.processRetries(ctx)
		}
	}
}

func (wm *WebhookManager) processRetries(ctx context.Context) {
	deliveries, err := wm.database.GetPendingWebhookDeliveries(10)
	if err != nil {
		log.Printf("Failed to get pending webhook deliveries: %v", err)
		return
	}

	for _, delivery := range deliveries {
		webhook, err := wm.database.GetWebhook(delivery.WebhookID)
		if err != nil || webhook == nil {
			log.Printf("Failed to get webhook for delivery: %v", err)
			continue
		}

		if !webhook.IsActive {
			continue
		}

		go wm.deliverWebhook(ctx, webhook, delivery)
	}
}

