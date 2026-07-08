package git

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// metricsCollector defines the interface for recording Git scan metrics.
type metricsCollector interface {
	// Clone metrics
	RecordCloneOperation(status string, reason string, duration time.Duration)

	// Scan metrics
	RecordCommitScanned()
	RecordRepoScanned(status string)
}

// Predefined status values
const (
	statusSuccess = "success"
	statusFailure = "failure"
)

// Predefined clone success reason
const (
	cloneSuccess = "success"
)

// Predefined clone failure reasons to avoid high cardinality
const (
	// Authentication/redirection errors
	cloneFailureAuth = "auth_error"

	// Rate limiting errors
	cloneFailureRateLimit = "rate_limit"

	// Permission errors
	cloneFailurePermission = "permission_denied"

	// Network/connection errors
	cloneFailureNetwork = "network_error"

	// Git reference errors
	cloneFailureReference = "reference_error"

	// Other/unknown errors
	cloneFailureOther = "other_error"

	// Clone exceeded the configured timeout
	cloneFailureTimeout = "timeout"
)

type collector struct {
	cloneOperations *prometheus.HistogramVec
	commitsScanned  prometheus.Counter
	reposScanned    *prometheus.CounterVec
}

var metricsInstance metricsCollector

func init() {
	// These are package-level metrics that are recorded by all git scans across the lifetime of the process.
	metricsInstance = &collector{
		// Labeled by status/reason only (not exit_code) to keep series count bounded -
		// reason is already a small fixed set (see ClassifyCloneError), exit_code is not.
		cloneOperations: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "git_clone_operations_duration_seconds",
			Help:      "Duration in seconds of git clone operations by status and reason",
			Buckets:   []float64{1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200},
		}, []string{"status", "reason"}),

		commitsScanned: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "git_commits_scanned_total",
			Help:      "Total number of git commits scanned",
		}),

		reposScanned: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "git_repos_scanned_total",
			Help:      "Total number of git repositories scanned by status (success/failure)",
		}, []string{"status"}),
	}
}

func (c *collector) RecordCloneOperation(status string, reason string, duration time.Duration) {
	c.cloneOperations.WithLabelValues(status, reason).Observe(duration.Seconds())
}

func (c *collector) RecordCommitScanned() {
	c.commitsScanned.Inc()
}

func (c *collector) RecordRepoScanned(status string) {
	c.reposScanned.WithLabelValues(status).Inc()
}

// ClassifyCloneError analyzes the error message and returns the appropriate failure reason
func ClassifyCloneError(errMsg string) string {
	switch {
	case strings.Contains(errMsg, "unable to update url base from redirection") &&
		strings.Contains(errMsg, "redirect:") && strings.Contains(errMsg, "users/sign_in"):
		return cloneFailureAuth

	case strings.Contains(errMsg, "The requested URL returned error: 429") ||
		strings.Contains(errMsg, "remote: Retry later"):
		return cloneFailureRateLimit

	case strings.Contains(errMsg, "The requested URL returned error: 403") ||
		strings.Contains(errMsg, "remote: You are not allowed to download code from this project"):
		return cloneFailurePermission

	case strings.Contains(errMsg, "RPC failed") ||
		strings.Contains(errMsg, "unexpected disconnect") ||
		strings.Contains(errMsg, "early EOF") ||
		strings.Contains(errMsg, "Problem (3) in the Chunked-Encoded data"):
		return cloneFailureNetwork

	case strings.Contains(errMsg, "cannot process") ||
		strings.Contains(errMsg, "multiple updates for ref") ||
		strings.Contains(errMsg, "invalid index-pack output"):
		return cloneFailureReference

	default:
		return cloneFailureOther
	}
}
