package engine

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	decodeLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "decode_latency",
			Help:      "Time spent decoding a chunk in microseconds",
			Buckets:   prometheus.ExponentialBuckets(50, 2, 20),
		},
		[]string{"decoder_type", "source_name"},
	)

	// Detector metrics.
	detectorExecutionCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "detector_execution_count",
			Help:      "Total number of times a detector has been executed.",
		},
		[]string{"detector_name", "job_id", "source_name"},
	)

	// Note this is the time taken to call FromData on each detector, not necessarily the time taken
	// to verify a credential via an API call. If the regex match within FromData does not match, the
	// detector will return early. For now this is a good proxy for the time taken to verify a credential.
	// TODO (ahrav)
	// We can work on a more fine-grained metric later.
	detectorExecutionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "detector_execution_duration",
			Help:      "Duration of detector execution in milliseconds.",
			Buckets:   prometheus.ExponentialBuckets(1, 5, 6),
		},
		[]string{"detector_name"},
	)

	jobBytesScanned = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "job_bytes_scanned",
		Help:      "Total number of bytes scanned for a job.",
	},
		[]string{"source_type", "source_name"},
	)

	scanBytesPerChunk = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "scan_bytes_per_chunk",
		Help:      "Total number of bytes in a chunk.",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 18),
	})

	jobChunksScanned = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "job_chunks_scanned",
		Help:      "Total number of chunks scanned for a job.",
	},
		[]string{"source_type", "source_name"},
	)

	detectBytesPerMatch = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "detect_bytes_per_match",
		Help:      "Total number of bytes used to detect a credential in a match per chunk.",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 18),
	})

	matchesPerChunk = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "matches_per_chunk",
		Help:      "Total number of matches found in a chunk.",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 10),
	})

	// Metrics around latency for the different stages of the pipeline.
	chunksScannedLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "chunk_scanned_latency",
		Help:      "Time taken to scan a chunk in microseconds.",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 22),
	})

	chunksDetectedLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "chunk_detected_latency",
		Help:      "Time taken to detect a chunk in microseconds.",
		Buckets:   prometheus.ExponentialBuckets(50, 2, 20),
	})

	chunksNotifiedLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "chunk_notified_latency",
		Help:      "Time taken to notify a chunk in milliseconds.",
		Buckets:   prometheus.ExponentialBuckets(5, 2, 12),
	})
)
