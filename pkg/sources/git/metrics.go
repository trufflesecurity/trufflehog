package git

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// metricsCollector defines the interface for recording Git scan metrics.
type metricsCollector interface {
	// Clone metrics
	RecordCloneOperation(status string, reason string, exitCode int)

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
)

type collector struct {
	cloneOperations *prometheus.CounterVec
	commitsScanned  prometheus.Counter
	reposScanned    *prometheus.CounterVec
}

var metricsInstance metricsCollector

func init() {
	// These are package-level metrics that are incremented by all git scans across the lifetime of the process.
	metricsInstance = &collector{
		cloneOperations: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "git_clone_operations_total",
			Help:      "Total number of git clone operations by status, reason, and exit code",
		}, []string{"status", "reason", "exit_code"}),

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

func (c *collector) RecordCloneOperation(status string, reason string, exitCode int) {
	c.cloneOperations.WithLabelValues(status, reason, fmt.Sprintf("%d", exitCode)).Inc()
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
