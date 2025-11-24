package models

// ScanRequest represents a request to initiate a scan
type ScanRequest struct {
	RepoURL         string                 `json:"repo_url" validate:"required,url"`
	Branch          string                 `json:"branch,omitempty"`
	SinceCommit     string                 `json:"since_commit,omitempty"`
	MaxDepth        int                    `json:"max_depth,omitempty"`
	IncludePaths    []string               `json:"include_paths,omitempty"`
	ExcludePaths    []string               `json:"exclude_paths,omitempty"`
	NoVerification  bool                   `json:"no_verification,omitempty"`
	OnlyVerified    bool                   `json:"only_verified,omitempty"`
	IncludeDetectors string                `json:"include_detectors,omitempty"`
	ExcludeDetectors string                `json:"exclude_detectors,omitempty"`
	Options         map[string]interface{} `json:"options,omitempty"`
}

// WebhookCreateRequest represents a request to create a webhook
type WebhookCreateRequest struct {
	URL            string            `json:"url" validate:"required,url"`
	Secret         string            `json:"secret" validate:"required,min=16"`
	Events         []string          `json:"events" validate:"required,min=1"`
	RetryCount     int               `json:"retry_count,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
}

// WebhookUpdateRequest represents a request to update a webhook
type WebhookUpdateRequest struct {
	URL            string            `json:"url,omitempty" validate:"omitempty,url"`
	Secret         string            `json:"secret,omitempty" validate:"omitempty,min=16"`
	Events         []string          `json:"events,omitempty" validate:"omitempty,min=1"`
	IsActive       *bool             `json:"is_active,omitempty"`
	RetryCount     *int              `json:"retry_count,omitempty"`
	TimeoutSeconds *int              `json:"timeout_seconds,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
}

