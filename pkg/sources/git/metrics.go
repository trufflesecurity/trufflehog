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

	// Checked before the generic 403/429 case below: when the git backend
	// itself explains a 403/429 with a "remote:" line, that's a permanent
	// failure (permission denial, SAML SSO enforcement, org policy, etc.),
	// not throttling — the backend only sends an explanatory message once
	// the request has been evaluated, whereas secondary-rate-limit responses
	// are either a bare 403/429 with no remote explanation or one of the
	// small, stable set of known throttling messages. Matching on "any
	// unrecognized remote: explanation" avoids having to enumerate every
	// provider's denial wording, which changes per provider and per feature
	// (SSO, fine-grained tokens, GitHub Apps, ...).
	case isRemotePermissionDenial(errMsg):
		return cloneFailurePermission

	case strings.Contains(errMsg, "The requested URL returned error: 429") ||
		strings.Contains(errMsg, "The requested URL returned error: 403") ||
		strings.Contains(errMsg, "remote: Retry later"):
		// A bare "403" during clone (no accompanying auth/permission message)
		// matches GitHub/GitLab secondary rate limiting and abuse-detection
		// responses, which are documented to return either 403 or 429.
		return cloneFailureRateLimit

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

// knownRateLimitRemoteMessages are the (small, stable) set of ways GitHub and
// GitLab phrase an actual throttling response in a "remote:" line. Any other
// "remote:" explanation accompanying a 403/429 is treated as a permanent
// failure rather than added here, since provider denial wording (permission,
// SSO, org policy, ...) varies far more than throttling wording does.
var knownRateLimitRemoteMessages = []string{
	"retry later",
	"secondary rate limit",
	"rate limit exceeded",
	"abuse detection",
}

// knownBenignRemoteProgressMessages are the small, standardized set of
// progress lines git-upload-pack prints to "remote:" during a normal clone
// (e.g. "remote: Counting objects: 100% (5/5), done."). These can appear
// ahead of an unrelated 403/429 or network failure, so they must not be
// mistaken for a denial explanation.
var knownBenignRemoteProgressMessages = []string{
	"enumerating objects",
	"counting objects",
	"compressing objects",
	"writing objects",
	"resolving deltas",
	"total ",
}

// knownBenignRemoteMessages is the combined set of "remote:" line contents
// that must NOT be treated as a permission denial: known throttling messages
// and known clone-progress output.
var knownBenignRemoteMessages = append(append([]string{}, knownRateLimitRemoteMessages...), knownBenignRemoteProgressMessages...)

// isRemotePermissionDenial reports whether errMsg contains a server-side
// "remote:" line explaining a 403/429 as something other than throttling or
// normal clone progress output, as opposed to a bare curl-level 403/429 with
// no explanation (or an explicit rate-limit message), which may just be
// transient rate limiting.
func isRemotePermissionDenial(errMsg string) bool {
	if !strings.Contains(errMsg, "403") && !strings.Contains(errMsg, "429") {
		return false
	}
	for _, line := range strings.Split(errMsg, "\n") {
		idx := strings.Index(line, "remote:")
		if idx == -1 {
			continue
		}
		remoteMsg := strings.ToLower(line[idx:])
		benign := false
		for _, marker := range knownBenignRemoteMessages {
			if strings.Contains(remoteMsg, marker) {
				benign = true
				break
			}
		}
		if !benign {
			return true
		}
	}
	return false
}
