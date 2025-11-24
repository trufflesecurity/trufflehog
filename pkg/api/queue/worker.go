package queue

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/db"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/models"
	"github.com/trufflesecurity/trufflehog/v3/pkg/api/webhooks"
)

type Worker struct {
	id            int
	queue         *RedisQueue
	database      *db.Database
	webhookMgr    *webhooks.WebhookManager
	maxConcurrent int
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

type WorkerPool struct {
	workers []*Worker
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

func NewWorker(id int, queue *RedisQueue, database *db.Database, webhookMgr *webhooks.WebhookManager) *Worker {
	maxConcurrent := 5
	if val := os.Getenv("MAX_CONCURRENT_SCANS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			maxConcurrent = n
		}
	}

	return &Worker{
		id:            id,
		queue:         queue,
		database:      database,
		webhookMgr:    webhookMgr,
		maxConcurrent: maxConcurrent,
		stopCh:        make(chan struct{}),
	}
}

func (w *Worker) Start(ctx context.Context) {
	w.wg.Add(1)
	go w.run(ctx)
}

func (w *Worker) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *Worker) run(ctx context.Context) {
	defer w.wg.Done()

	log.Printf("Worker %d started", w.id)

	for {
		select {
		case <-w.stopCh:
			log.Printf("Worker %d stopping", w.id)
			return
		case <-ctx.Done():
			log.Printf("Worker %d context cancelled", w.id)
			return
		default:
			job, err := w.queue.DequeueScanJob(ctx, 5*time.Second)
			if err != nil {
				log.Printf("Worker %d: error dequeuing job: %v", w.id, err)
				time.Sleep(1 * time.Second)
				continue
			}

			if job == nil {
				continue
			}

			log.Printf("Worker %d: processing job %s", w.id, job.JobID)
			w.processJob(ctx, job)
		}
	}
}

func (w *Worker) processJob(ctx context.Context, job *JobMessage) {
	jobID := job.JobID

	// Update status to running
	if err := w.database.UpdateScanJobStatus(jobID, "running", 0, nil); err != nil {
		log.Printf("Failed to update job status: %v", err)
		return
	}

	if err := w.queue.SetJobStatus(ctx, jobID, "running", 24*time.Hour); err != nil {
		log.Printf("Failed to set Redis job status: %v", err)
	}

	// Trigger scan.started webhook
	w.webhookMgr.TriggerEvent(ctx, "scan.started", map[string]interface{}{
		"job_id":   jobID.String(),
		"repo_url": job.RepoURL,
		"status":   "running",
	}, &jobID)

	// Execute scan
	err := w.executeScan(ctx, job)

	if err != nil {
		errMsg := err.Error()
		if updateErr := w.database.UpdateScanJobStatus(jobID, "failed", 100, &errMsg); updateErr != nil {
			log.Printf("Failed to update job status: %v", updateErr)
		}

		if setErr := w.queue.SetJobStatus(ctx, jobID, "failed", 24*time.Hour); setErr != nil {
			log.Printf("Failed to set Redis job status: %v", setErr)
		}

		// Trigger scan.failed webhook
		w.webhookMgr.TriggerEvent(ctx, "scan.failed", map[string]interface{}{
			"job_id":   jobID.String(),
			"repo_url": job.RepoURL,
			"status":   "failed",
			"error":    errMsg,
		}, &jobID)

		log.Printf("Worker %d: job %s failed: %v", w.id, jobID, err)
		return
	}

	// Update status to completed
	if err := w.database.UpdateScanJobStatus(jobID, "completed", 100, nil); err != nil {
		log.Printf("Failed to update job status: %v", err)
		return
	}

	if err := w.queue.SetJobStatus(ctx, jobID, "completed", 24*time.Hour); err != nil {
		log.Printf("Failed to set Redis job status: %v", err)
	}

	// Get final job stats
	finalJob, _ := w.database.GetScanJob(jobID)
	
	// Trigger scan.completed webhook
	w.webhookMgr.TriggerEvent(ctx, "scan.completed", map[string]interface{}{
		"job_id":             jobID.String(),
		"repo_url":           job.RepoURL,
		"status":             "completed",
		"chunks_scanned":     finalJob.ChunksScanned,
		"bytes_scanned":      finalJob.BytesScanned,
		"secrets_found":      finalJob.SecretsFound,
		"verified_secrets":   finalJob.VerifiedSecrets,
		"unverified_secrets": finalJob.UnverifiedSecrets,
	}, &jobID)

	log.Printf("Worker %d: job %s completed successfully", w.id, jobID)
}

func (w *Worker) executeScan(ctx context.Context, job *JobMessage) error {
	// Find trufflehog binary
	trufflehogBin, err := findTrufflehogBinary()
	if err != nil {
		return fmt.Errorf("failed to find trufflehog binary: %w", err)
	}

	// Create temporary directory for results
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("trufflehog-scan-%s", job.JobID.String()))
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Build command arguments
	args := []string{
		"git",
		job.RepoURL,
		"--json",
		"--no-update",
	}

	// Add optional parameters
	if branch := getStringOption(job.Options, "branch", ""); branch != "" {
		args = append(args, "--branch", branch)
	}
	if sinceCommit := getStringOption(job.Options, "since_commit", ""); sinceCommit != "" {
		args = append(args, "--since-commit", sinceCommit)
	}
	if maxDepth := getIntOption(job.Options, "max_depth", 0); maxDepth > 0 {
		args = append(args, "--max-depth", strconv.Itoa(maxDepth))
	}
	if getBoolOption(job.Options, "no_verification", false) {
		args = append(args, "--no-verification")
	}
	if getBoolOption(job.Options, "only_verified", false) {
		args = append(args, "--only-verified")
	}

	// Execute trufflehog
	cmd := exec.CommandContext(ctx, trufflehogBin, args...)
	
	// Capture output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start trufflehog: %w", err)
	}

	// Process results in real-time
	scanner := bufio.NewScanner(stdout)
	verified := 0
	unverified := 0
	totalResults := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse JSON result
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			log.Printf("Failed to parse result line: %v", err)
			continue
		}

		// Store result in database
		scanResult := w.parseResult(job.JobID, result)
		if err := w.database.CreateScanResult(scanResult); err != nil {
			log.Printf("Failed to store scan result: %v", err)
		}

		// Count results
		totalResults++
		if scanResult.Verified {
			verified++
		} else {
			unverified++
		}

		// Update progress periodically
		if totalResults%10 == 0 {
			progress := 50 // Approximate progress
			w.database.UpdateScanJobStatus(job.JobID, "running", progress, nil)
			w.queue.SetJobProgress(ctx, job.JobID, progress, 24*time.Hour)
		}
	}

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		// Check if it's just a non-zero exit (which is normal if secrets found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 183 means secrets found, which is not an error
			if exitErr.ExitCode() != 183 {
				return fmt.Errorf("trufflehog exited with error: %w", err)
			}
		} else {
			return fmt.Errorf("trufflehog execution error: %w", err)
		}
	}

	// Update final metrics
	err = w.database.UpdateScanJobMetrics(
		job.JobID,
		0, // chunks not available from CLI
		0, // bytes not available from CLI
		totalResults,
		verified,
		unverified,
	)
	if err != nil {
		log.Printf("Failed to update job metrics: %v", err)
	}

	return nil
}

func findTrufflehogBinary() (string, error) {
	// Check common locations
	locations := []string{
		"/opt/trufflehog/trufflehog",           // Deployed location
		"/root/trufflehog/trufflehog",          // Build directory
		"/usr/local/bin/trufflehog",            // System install
		"/usr/bin/trufflehog",                  // System install
		"./trufflehog",                         // Current directory
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc, nil
		}
	}

	// Try PATH
	path, err := exec.LookPath("trufflehog")
	if err == nil {
		return path, nil
	}

	return "", fmt.Errorf("trufflehog binary not found in common locations")
}

func (w *Worker) parseResult(jobID uuid.UUID, result map[string]interface{}) *models.ScanResult {
	scanResult := &models.ScanResult{
		ID:           uuid.New(),
		JobID:        jobID,
		RawResult:    result,
		SourceMetadata: make(map[string]interface{}),
	}

	// Extract common fields
	if detectorName, ok := result["DetectorName"].(string); ok {
		scanResult.DetectorName = detectorName
	}
	if detectorType, ok := result["DetectorType"].(float64); ok {
		scanResult.DetectorType = fmt.Sprintf("%d", int(detectorType))
	}
	if verified, ok := result["Verified"].(bool); ok {
		scanResult.Verified = verified
	}
	if raw, ok := result["Raw"].(string); ok {
		scanResult.Secret = raw
		scanResult.RedactedSecret = redactSecret(raw)
	}

	// Extract source metadata
	if sourceMetadata, ok := result["SourceMetadata"].(map[string]interface{}); ok {
		scanResult.SourceMetadata = sourceMetadata
		
		// Extract specific fields
		if data, ok := sourceMetadata["Data"].(map[string]interface{}); ok {
			if git, ok := data["Git"].(map[string]interface{}); ok {
				if commit, ok := git["commit"].(string); ok {
					scanResult.CommitHash = commit
				}
				if file, ok := git["file"].(string); ok {
					scanResult.FilePath = file
				}
				if line, ok := git["line"].(float64); ok {
					scanResult.LineNumber = int(line)
				}
			}
		}
	}

	return scanResult
}

func redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

func getStringOption(options map[string]interface{}, key, defaultValue string) string {
	if val, ok := options[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

func getIntOption(options map[string]interface{}, key string, defaultValue int) int {
	if val, ok := options[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultValue
}

func getBoolOption(options map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := options[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// WorkerPool management

func NewWorkerPool(numWorkers int, queue *RedisQueue, database *db.Database, webhookMgr *webhooks.WebhookManager) *WorkerPool {
	pool := &WorkerPool{
		workers: make([]*Worker, numWorkers),
		stopCh:  make(chan struct{}),
	}

	for i := 0; i < numWorkers; i++ {
		pool.workers[i] = NewWorker(i+1, queue, database, webhookMgr)
	}

	return pool
}

func (p *WorkerPool) Start(ctx context.Context) {
	for _, worker := range p.workers {
		worker.Start(ctx)
	}
}

func (p *WorkerPool) Stop() {
	for _, worker := range p.workers {
		worker.Stop()
	}
}

