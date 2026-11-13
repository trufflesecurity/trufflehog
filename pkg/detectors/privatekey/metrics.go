package privatekey

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// crackDuration times how long the encrypted-key passphrase walk takes, by
// key format and KDF round-count class. This is the first metric registered
// from inside a detector package (engine-level metrics are the established
// pattern); only the detector can see the format and round count, and both
// label values are bounded: format is one of three constants, kdf_rounds is
// a bucket rather than the raw count, because the count is an
// attacker-controlled header value. The bucket boundaries live beside their
// constants in keymeta.go. The histogram times the crack call only, so it
// cannot distinguish slow cracking from a slow verifier.
//
// Aborted observations are kept deliberately: an aborted walk still held
// its scan worker for the time observed, which is exactly the hold time
// this metric exists to size, so the observation stays in the series with
// its duration censored at the deadline - indistinguishable from a
// completed walk. The V(2) log line, not the metric, carries the outcome.
var crackDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "privatekey_crack_duration_seconds",
		Help:      "Duration in seconds of private key crack attempts, by key format and KDF round-count class. Aborted walks are included with their duration censored at the deadline.",
		// Buckets span sub-second legacy-PEM walks at the floor through
		// ~24s default-round OpenSSH walks; aborted walks land near the
		// 10s detection deadline, inside the range.
		Buckets: prometheus.ExponentialBuckets(0.05, 4, 9),
	},
	[]string{"format", "kdf_rounds"},
)
