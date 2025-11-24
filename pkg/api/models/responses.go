package models

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// ScanJobResponse represents a scan job creation response
type ScanJobResponse struct {
	JobID   string `json:"job_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// ScanJobStatusResponse represents a scan job status response
type ScanJobStatusResponse struct {
	Job     *ScanJob      `json:"job"`
	Results []*ScanResult `json:"results,omitempty"`
	Page    *PageInfo     `json:"page,omitempty"`
}

// PageInfo represents pagination information
type PageInfo struct {
	Total      int `json:"total"`
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
}

// DetectorsResponse represents a list of detectors
type DetectorsResponse struct {
	Detectors []DetectorInfo `json:"detectors"`
	Total     int            `json:"total"`
}

// WebhookListResponse represents a list of webhooks
type WebhookListResponse struct {
	Webhooks []*WebhookConfig `json:"webhooks"`
	Total    int              `json:"total"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status   string            `json:"status"`
	Version  string            `json:"version"`
	Services map[string]string `json:"services"`
}

