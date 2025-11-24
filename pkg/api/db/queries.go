package db

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
)

// Scan Job Operations

func (d *Database) CreateScanJob(repoURL string, options map[string]interface{}, apiKeyID *uuid.UUID) (*models.ScanJob, error) {
	job := &models.ScanJob{
		ID:        uuid.New(),
		RepoURL:   repoURL,
		Status:    "queued",
		Progress:  0,
		CreatedAt: time.Now(),
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	query := `
		INSERT INTO scan_jobs (id, repo_url, status, progress, options, api_key_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at`

	err = d.DB.QueryRow(query, job.ID, job.RepoURL, job.Status, job.Progress, optionsJSON, apiKeyID).
		Scan(&job.CreatedAt)
	if err != nil {
		return nil, err
	}

	return job, nil
}

func (d *Database) GetScanJob(jobID uuid.UUID) (*models.ScanJob, error) {
	job := &models.ScanJob{}
	var optionsJSON []byte
	var startedAt, completedAt sql.NullTime
	var errorMsg sql.NullString

	query := `
		SELECT id, repo_url, status, progress, created_at, started_at, completed_at, 
		       error_message, options, chunks_scanned, bytes_scanned, secrets_found,
		       verified_secrets, unverified_secrets
		FROM scan_jobs WHERE id = $1`

	err := d.DB.QueryRow(query, jobID).Scan(
		&job.ID, &job.RepoURL, &job.Status, &job.Progress, &job.CreatedAt,
		&startedAt, &completedAt, &errorMsg, &optionsJSON,
		&job.ChunksScanned, &job.BytesScanned, &job.SecretsFound,
		&job.VerifiedSecrets, &job.UnverifiedSecrets,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if startedAt.Valid {
		job.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		job.CompletedAt = &completedAt.Time
	}
	if errorMsg.Valid {
		job.ErrorMessage = errorMsg.String
	}

	if len(optionsJSON) > 0 {
		json.Unmarshal(optionsJSON, &job.Options)
	}

	return job, nil
}

func (d *Database) UpdateScanJobStatus(jobID uuid.UUID, status string, progress int, errorMsg *string) error {
	query := `
		UPDATE scan_jobs 
		SET status = $1, progress = $2, error_message = $3,
		    started_at = CASE WHEN status = 'queued' AND $1 = 'running' THEN NOW() ELSE started_at END,
		    completed_at = CASE WHEN $1 IN ('completed', 'failed', 'cancelled') THEN NOW() ELSE completed_at END
		WHERE id = $4`

	_, err := d.DB.Exec(query, status, progress, errorMsg, jobID)
	return err
}

func (d *Database) UpdateScanJobMetrics(jobID uuid.UUID, chunks, bytes int64, secretsFound, verified, unverified int) error {
	query := `
		UPDATE scan_jobs 
		SET chunks_scanned = $1, bytes_scanned = $2, secrets_found = $3,
		    verified_secrets = $4, unverified_secrets = $5
		WHERE id = $6`

	_, err := d.DB.Exec(query, chunks, bytes, secretsFound, verified, unverified, jobID)
	return err
}

// Scan Result Operations

func (d *Database) CreateScanResult(result *models.ScanResult) error {
	rawJSON, err := json.Marshal(result.RawResult)
	if err != nil {
		return err
	}

	metadataJSON, err := json.Marshal(result.SourceMetadata)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO scan_results 
		(id, job_id, detector_type, detector_name, secret, verified, verification_error,
		 raw_result, source_metadata, line_number, file_path, commit_hash, redacted_secret)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	_, err = d.DB.Exec(query,
		result.ID, result.JobID, result.DetectorType, result.DetectorName,
		result.Secret, result.Verified, result.VerificationError,
		rawJSON, metadataJSON, result.LineNumber, result.FilePath,
		result.CommitHash, result.RedactedSecret,
	)

	return err
}

func (d *Database) GetScanResults(jobID uuid.UUID, limit, offset int) ([]*models.ScanResult, int, error) {
	var total int
	countQuery := `SELECT COUNT(*) FROM scan_results WHERE job_id = $1`
	err := d.DB.QueryRow(countQuery, jobID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, job_id, detector_type, detector_name, secret, verified, 
		       verification_error, raw_result, created_at, source_metadata,
		       line_number, file_path, commit_hash, redacted_secret
		FROM scan_results 
		WHERE job_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := d.DB.Query(query, jobID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	results := []*models.ScanResult{}
	for rows.Next() {
		r := &models.ScanResult{}
		var rawJSON, metadataJSON []byte
		var verificationError sql.NullString
		var lineNumber sql.NullInt64
		var filePath, commitHash, redactedSecret sql.NullString

		err := rows.Scan(
			&r.ID, &r.JobID, &r.DetectorType, &r.DetectorName,
			&r.Secret, &r.Verified, &verificationError,
			&rawJSON, &r.CreatedAt, &metadataJSON,
			&lineNumber, &filePath, &commitHash, &redactedSecret,
		)
		if err != nil {
			return nil, 0, err
		}

		if verificationError.Valid {
			r.VerificationError = verificationError.String
		}
		if lineNumber.Valid {
			r.LineNumber = int(lineNumber.Int64)
		}
		if filePath.Valid {
			r.FilePath = filePath.String
		}
		if commitHash.Valid {
			r.CommitHash = commitHash.String
		}
		if redactedSecret.Valid {
			r.RedactedSecret = redactedSecret.String
		}

		json.Unmarshal(rawJSON, &r.RawResult)
		json.Unmarshal(metadataJSON, &r.SourceMetadata)

		results = append(results, r)
	}

	return results, total, rows.Err()
}

// Webhook Operations

func (d *Database) CreateWebhook(webhook *models.WebhookConfig) error {
	webhook.ID = uuid.New()
	webhook.CreatedAt = time.Now()
	webhook.UpdatedAt = time.Now()

	eventsJSON, err := json.Marshal(webhook.Events)
	if err != nil {
		return err
	}

	headersJSON, err := json.Marshal(webhook.Headers)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO webhook_configs 
		(id, url, secret, events, is_active, api_key_id, retry_count, timeout_seconds, headers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = d.DB.Exec(query,
		webhook.ID, webhook.URL, webhook.Secret, eventsJSON,
		webhook.IsActive, webhook.APIKeyID, webhook.RetryCount,
		webhook.TimeoutSeconds, headersJSON,
	)

	return err
}

func (d *Database) GetWebhook(webhookID uuid.UUID) (*models.WebhookConfig, error) {
	webhook := &models.WebhookConfig{}
	var eventsJSON, headersJSON []byte
	var apiKeyID sql.NullString

	query := `
		SELECT id, url, secret, events, is_active, created_at, updated_at,
		       api_key_id, retry_count, timeout_seconds, headers
		FROM webhook_configs WHERE id = $1`

	err := d.DB.QueryRow(query, webhookID).Scan(
		&webhook.ID, &webhook.URL, &webhook.Secret, &eventsJSON,
		&webhook.IsActive, &webhook.CreatedAt, &webhook.UpdatedAt,
		&apiKeyID, &webhook.RetryCount, &webhook.TimeoutSeconds, &headersJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if apiKeyID.Valid {
		id, _ := uuid.Parse(apiKeyID.String)
		webhook.APIKeyID = &id
	}

	json.Unmarshal(eventsJSON, &webhook.Events)
	json.Unmarshal(headersJSON, &webhook.Headers)

	return webhook, nil
}

func (d *Database) ListWebhooks(apiKeyID *uuid.UUID) ([]*models.WebhookConfig, error) {
	query := `
		SELECT id, url, secret, events, is_active, created_at, updated_at,
		       api_key_id, retry_count, timeout_seconds, headers
		FROM webhook_configs`

	var rows *sql.Rows
	var err error

	if apiKeyID != nil {
		query += " WHERE api_key_id = $1"
		rows, err = d.DB.Query(query, apiKeyID)
	} else {
		rows, err = d.DB.Query(query)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	webhooks := []*models.WebhookConfig{}
	for rows.Next() {
		w := &models.WebhookConfig{}
		var eventsJSON, headersJSON []byte
		var apiKeyID sql.NullString

		err := rows.Scan(
			&w.ID, &w.URL, &w.Secret, &eventsJSON,
			&w.IsActive, &w.CreatedAt, &w.UpdatedAt,
			&apiKeyID, &w.RetryCount, &w.TimeoutSeconds, &headersJSON,
		)
		if err != nil {
			return nil, err
		}

		if apiKeyID.Valid {
			id, _ := uuid.Parse(apiKeyID.String)
			w.APIKeyID = &id
		}

		json.Unmarshal(eventsJSON, &w.Events)
		json.Unmarshal(headersJSON, &w.Headers)

		webhooks = append(webhooks, w)
	}

	return webhooks, rows.Err()
}

func (d *Database) UpdateWebhook(webhookID uuid.UUID, url, secret string, events []string, isActive bool) error {
	eventsJSON, err := json.Marshal(events)
	if err != nil {
		return err
	}

	query := `
		UPDATE webhook_configs 
		SET url = $1, secret = $2, events = $3, is_active = $4, updated_at = NOW()
		WHERE id = $5`

	_, err = d.DB.Exec(query, url, secret, eventsJSON, isActive, webhookID)
	return err
}

func (d *Database) DeleteWebhook(webhookID uuid.UUID) error {
	query := `DELETE FROM webhook_configs WHERE id = $1`
	_, err := d.DB.Exec(query, webhookID)
	return err
}

// Webhook Delivery Operations

func (d *Database) CreateWebhookDelivery(delivery *models.WebhookDelivery) error {
	delivery.ID = uuid.New()
	delivery.CreatedAt = time.Now()

	payloadJSON, err := json.Marshal(delivery.Payload)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO webhook_deliveries 
		(id, webhook_id, job_id, event, payload, retry_count, next_retry_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err = d.DB.Exec(query,
		delivery.ID, delivery.WebhookID, delivery.JobID,
		delivery.Event, payloadJSON, delivery.RetryCount, delivery.NextRetryAt,
	)

	return err
}

func (d *Database) UpdateWebhookDelivery(deliveryID uuid.UUID, status int, responseBody, errorMsg string) error {
	query := `
		UPDATE webhook_deliveries 
		SET response_status = $1, response_body = $2, error_message = $3, 
		    delivered_at = NOW()
		WHERE id = $4`

	_, err := d.DB.Exec(query, status, responseBody, errorMsg, deliveryID)
	return err
}

func (d *Database) GetPendingWebhookDeliveries(limit int) ([]*models.WebhookDelivery, error) {
	query := `
		SELECT id, webhook_id, job_id, event, payload, retry_count, next_retry_at
		FROM webhook_deliveries
		WHERE delivered_at IS NULL 
		  AND (next_retry_at IS NULL OR next_retry_at <= NOW())
		ORDER BY created_at ASC
		LIMIT $1`

	rows, err := d.DB.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	deliveries := []*models.WebhookDelivery{}
	for rows.Next() {
		d := &models.WebhookDelivery{}
		var payloadJSON []byte
		var jobID sql.NullString
		var nextRetryAt sql.NullTime

		err := rows.Scan(
			&d.ID, &d.WebhookID, &jobID, &d.Event,
			&payloadJSON, &d.RetryCount, &nextRetryAt,
		)
		if err != nil {
			return nil, err
		}

		if jobID.Valid {
			id, _ := uuid.Parse(jobID.String)
			d.JobID = &id
		}

		if nextRetryAt.Valid {
			d.NextRetryAt = &nextRetryAt.Time
		}

		json.Unmarshal(payloadJSON, &d.Payload)

		deliveries = append(deliveries, d)
	}

	return deliveries, rows.Err()
}

func (d *Database) GetActiveWebhooksForEvent(event string) ([]*models.WebhookConfig, error) {
	query := `
		SELECT id, url, secret, events, is_active, created_at, updated_at,
		       api_key_id, retry_count, timeout_seconds, headers
		FROM webhook_configs
		WHERE is_active = true AND $1 = ANY(events)`

	rows, err := d.DB.Query(query, event)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	webhooks := []*models.WebhookConfig{}
	for rows.Next() {
		w := &models.WebhookConfig{}
		var eventsJSON, headersJSON []byte
		var apiKeyID sql.NullString

		err := rows.Scan(
			&w.ID, &w.URL, &w.Secret, &eventsJSON,
			&w.IsActive, &w.CreatedAt, &w.UpdatedAt,
			&apiKeyID, &w.RetryCount, &w.TimeoutSeconds, &headersJSON,
		)
		if err != nil {
			return nil, err
		}

		if apiKeyID.Valid {
			id, _ := uuid.Parse(apiKeyID.String)
			w.APIKeyID = &id
		}

		json.Unmarshal(eventsJSON, &w.Events)
		json.Unmarshal(headersJSON, &w.Headers)

		webhooks = append(webhooks, w)
	}

	return webhooks, rows.Err()
}

