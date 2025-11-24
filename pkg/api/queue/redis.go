package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	ScanJobQueue    = "scan_jobs"
	WebhookQueue    = "webhook_deliveries"
	JobStatusPrefix = "job:status:"
)

type RedisQueue struct {
	client *redis.Client
}

type JobMessage struct {
	JobID     uuid.UUID              `json:"job_id"`
	RepoURL   string                 `json:"repo_url"`
	Options   map[string]interface{} `json:"options"`
	CreatedAt time.Time              `json:"created_at"`
}

func NewRedisQueue() (*RedisQueue, error) {
	host := getEnv("REDIS_HOST", "localhost")
	port := getEnv("REDIS_PORT", "6379")
	password := getEnv("REDIS_PASSWORD", "")

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port),
		Password: password,
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisQueue{client: client}, nil
}

func (q *RedisQueue) Close() error {
	return q.client.Close()
}

func (q *RedisQueue) EnqueueScanJob(ctx context.Context, job *JobMessage) error {
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	return q.client.LPush(ctx, ScanJobQueue, data).Err()
}

func (q *RedisQueue) DequeueScanJob(ctx context.Context, timeout time.Duration) (*JobMessage, error) {
	result, err := q.client.BRPop(ctx, timeout, ScanJobQueue).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to dequeue job: %w", err)
	}

	if len(result) < 2 {
		return nil, fmt.Errorf("invalid queue result")
	}

	var job JobMessage
	if err := json.Unmarshal([]byte(result[1]), &job); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}

	return &job, nil
}

func (q *RedisQueue) SetJobStatus(ctx context.Context, jobID uuid.UUID, status string, ttl time.Duration) error {
	key := fmt.Sprintf("%s%s", JobStatusPrefix, jobID.String())
	return q.client.Set(ctx, key, status, ttl).Err()
}

func (q *RedisQueue) GetJobStatus(ctx context.Context, jobID uuid.UUID) (string, error) {
	key := fmt.Sprintf("%s%s", JobStatusPrefix, jobID.String())
	result, err := q.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return result, err
}

func (q *RedisQueue) SetJobProgress(ctx context.Context, jobID uuid.UUID, progress int, ttl time.Duration) error {
	key := fmt.Sprintf("job:progress:%s", jobID.String())
	return q.client.Set(ctx, key, progress, ttl).Err()
}

func (q *RedisQueue) GetJobProgress(ctx context.Context, jobID uuid.UUID) (int, error) {
	key := fmt.Sprintf("job:progress:%s", jobID.String())
	result, err := q.client.Get(ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return result, err
}

func (q *RedisQueue) GetQueueLength(ctx context.Context, queueName string) (int64, error) {
	return q.client.LLen(ctx, queueName).Result()
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

