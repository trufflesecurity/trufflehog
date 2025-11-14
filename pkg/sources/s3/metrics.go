package s3

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// metricsCollector defines the interface for recording S3 scan metrics.
type metricsCollector interface {
	// Object metrics.

	RecordObjectScanned(bucket string, sizeBytes float64)
	RecordObjectSkipped(bucket, reason string, sizeBytes float64)
	RecordObjectError(bucket string)

	// Role metrics.

	RecordRoleScanned(roleArn string)
	RecordBucketForRole(roleArn string)
}

type collector struct {
	objectsScanned *prometheus.HistogramVec
	objectsSkipped *prometheus.HistogramVec
	objectsErrors  *prometheus.CounterVec
	rolesScanned   *prometheus.GaugeVec
	bucketsPerRole *prometheus.GaugeVec
}

var metricsInstance metricsCollector

func init() {
	metricsInstance = &collector{
		objectsScanned: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "objects_scanned_bytes",
			Help:      "Size distribution of successfully scanned S3 objects in bytes",
			// 64B, 512B, 4KB, 32KB, 256KB, 2MB, 16MB, 128MB, 1GB.
			Buckets: prometheus.ExponentialBuckets(64, 8, 9),
		}, []string{"bucket"}),

		objectsSkipped: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "objects_skipped_bytes",
			Help:      "Size distribution of skipped S3 objects in bytes",
			// 64B, 512B, 4KB, 32KB, 256KB, 2MB, 16MB, 128MB, 1GB.
			Buckets: prometheus.ExponentialBuckets(64, 8, 9),
		}, []string{"bucket", "reason"}),

		objectsErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "objects_errors_total",
			Help:      "Total number of errors encountered during S3 scan",
		}, []string{"bucket"}),

		rolesScanned: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "roles_scanned",
			Help:      "Number of AWS roles being scanned",
		}, []string{"role_arn"}),

		bucketsPerRole: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "buckets_per_role",
			Help:      "Number of buckets accessible per AWS role",
		}, []string{"role_arn"}),
	}
}

func (c *collector) RecordObjectScanned(bucket string, sizeBytes float64) {
	c.objectsScanned.WithLabelValues(bucket).Observe(sizeBytes)
}

func (c *collector) RecordObjectSkipped(bucket, reason string, sizeBytes float64) {
	c.objectsSkipped.WithLabelValues(bucket, reason).Observe(sizeBytes)
}

func (c *collector) RecordObjectError(bucket string) {
	c.objectsErrors.WithLabelValues(bucket).Inc()
}

const defaultRoleARN = "default"

func (c *collector) RecordRoleScanned(roleArn string) {
	if roleArn == "" {
		roleArn = defaultRoleARN
	}
	c.rolesScanned.WithLabelValues(roleArn).Set(1)
}

func (c *collector) RecordBucketForRole(roleArn string) {
	if roleArn == "" {
		roleArn = defaultRoleARN
	}
	c.bucketsPerRole.WithLabelValues(roleArn).Inc()
}
