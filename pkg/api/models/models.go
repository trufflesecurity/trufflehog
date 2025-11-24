package models

import (
	"time"

	"github.com/google/uuid"
)

// ScanJob represents a scanning job
type ScanJob struct {
	ID                uuid.UUID              `json:"id"`
	RepoURL           string                 `json:"repo_url"`
	Status            string                 `json:"status"`
	Progress          int                    `json:"progress"`
	CreatedAt         time.Time              `json:"created_at"`
	StartedAt         *time.Time             `json:"started_at,omitempty"`
	CompletedAt       *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage      string                 `json:"error_message,omitempty"`
	Options           map[string]interface{} `json:"options,omitempty"`
	ChunksScanned     int64                  `json:"chunks_scanned"`
	BytesScanned      int64                  `json:"bytes_scanned"`
	SecretsFound      int                    `json:"secrets_found"`
	VerifiedSecrets   int                    `json:"verified_secrets"`
	UnverifiedSecrets int                    `json:"unverified_secrets"`
}

// ScanResult represents a detected secret
type ScanResult struct {
	ID                uuid.UUID              `json:"id"`
	JobID             uuid.UUID              `json:"job_id"`
	DetectorType      string                 `json:"detector_type"`
	DetectorName      string                 `json:"detector_name"`
	Secret            string                 `json:"secret,omitempty"`
	RedactedSecret    string                 `json:"redacted_secret"`
	Verified          bool                   `json:"verified"`
	VerificationError string                 `json:"verification_error,omitempty"`
	RawResult         map[string]interface{} `json:"raw_result"`
	CreatedAt         time.Time              `json:"created_at"`
	SourceMetadata    map[string]interface{} `json:"source_metadata,omitempty"`
	LineNumber        int                    `json:"line_number,omitempty"`
	FilePath          string                 `json:"file_path,omitempty"`
	CommitHash        string                 `json:"commit_hash,omitempty"`
}

// WebhookConfig represents a webhook configuration
type WebhookConfig struct {
	ID             uuid.UUID              `json:"id"`
	URL            string                 `json:"url"`
	Secret         string                 `json:"secret,omitempty"`
	Events         []string               `json:"events"`
	IsActive       bool                   `json:"is_active"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	APIKeyID       *uuid.UUID             `json:"api_key_id,omitempty"`
	RetryCount     int                    `json:"retry_count"`
	TimeoutSeconds int                    `json:"timeout_seconds"`
	Headers        map[string]string      `json:"headers,omitempty"`
}

// WebhookDelivery represents a webhook delivery attempt
type WebhookDelivery struct {
	ID             uuid.UUID              `json:"id"`
	WebhookID      uuid.UUID              `json:"webhook_id"`
	JobID          *uuid.UUID             `json:"job_id,omitempty"`
	Event          string                 `json:"event"`
	Payload        map[string]interface{} `json:"payload"`
	ResponseStatus int                    `json:"response_status,omitempty"`
	ResponseBody   string                 `json:"response_body,omitempty"`
	DeliveredAt    *time.Time             `json:"delivered_at,omitempty"`
	RetryCount     int                    `json:"retry_count"`
	NextRetryAt    *time.Time             `json:"next_retry_at,omitempty"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
}

// DetectorInfo represents metadata about a detector
type DetectorInfo struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Keywords []string `json:"keywords"`
	Version  int      `json:"version"`
}

