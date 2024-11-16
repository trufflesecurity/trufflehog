package s3

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// metricsCollector defines the interface for recording S3 scan metrics.
type metricsCollector interface {
	// Object metrics.

	RecordObjectScanned(bucket string)
	RecordObjectSkipped(bucket, reason string)
	RecordObjectError(bucket string)

	// Role metrics.

	RecordRoleScanned(roleArn string)
	RecordBucketForRole(roleArn string)
}

type collector struct {
	objectsScanned *prometheus.CounterVec
	objectsSkipped *prometheus.CounterVec
	objectsErrors  *prometheus.CounterVec
	rolesScanned   *prometheus.GaugeVec
	bucketsPerRole *prometheus.GaugeVec
}

var metricsInstance metricsCollector

func init() {
	metricsInstance = &collector{
		objectsScanned: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "objects_scanned_total",
			Help:      "Total number of S3 objects successfully scanned",
		}, []string{"bucket"}),

		objectsSkipped: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "objects_skipped_total",
			Help:      "Total number of S3 objects skipped during scan",
		}, []string{"bucket", "reason"}),

		objectsErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "objects_errors_total",
			Help:      "Total number of errors encountered during S3 scan",
		}, []string{"bucket"}),

		rolesScanned: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "roles_scanned",
			Help:      "Number of AWS roles being scanned",
		}, []string{"role_arn"}),

		bucketsPerRole: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "buckets_per_role",
			Help:      "Number of buckets accessible per AWS role",
		}, []string{"role_arn"}),
	}
}

func (c *collector) RecordObjectScanned(bucket string) {
	c.objectsScanned.WithLabelValues(bucket).Inc()
}

func (c *collector) RecordObjectSkipped(bucket, reason string) {
	c.objectsSkipped.WithLabelValues(bucket, reason).Inc()
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
