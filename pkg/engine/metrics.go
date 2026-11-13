package engine

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	// Detector metrics.
	detectorExecutionCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "detector_execution_count",
			Help:      "Total number of times a detector has been executed.",
		},
		[]string{"detector_name", "source_type", "source_name"},
	)

	// Note this is the time taken by one FromData call, made once per keyword match, not necessarily the time taken
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

	// Timeout-overrun metrics. The overrun timer in detectChunk arms at the detection timeout plus a one-second
	// grace, so these count calls that ran past that grace deadline, not merely past the bare timeout. The
	// histogram buckets start at 10 seconds because the execution-duration histogram above tops out near 3
	// seconds and would drop every overrun into +Inf. That floor assumes the default 10 s detection timeout:
	// SetDetectorTimeout is exported, and a smaller value lets overruns finish below 10 s, where they all land in
	// the first bucket with no resolution between them.
	detectorTimeoutIgnoredTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "detector_timeout_ignored_total",
			Help:      "Total number of FromData calls whose overrun timer fired.",
		},
		[]string{"detector_name"},
	)

	detectorWorkersOverTimeout = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "detector_workers_over_timeout",
			Help:      "Workers currently inside a FromData call that kept running past the detection timeout plus its one-second grace.",
		},
		[]string{"detector_name"},
	)

	detectorOverrunDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "detector_overrun_duration_seconds",
			Help:      "Duration in seconds of FromData calls that overran the detection timeout grace (total call duration, not just the overhang).",
			Buckets:   prometheus.ExponentialBuckets(10, 2, 10),
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

	scanBytesPerChunk = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "scan_bytes_per_chunk",
		Help:      "Total number of bytes in a chunk.",
		Buckets:   prometheus.ExponentialBuckets(1, 2, 18),
	},
		[]string{"source_type"},
	)

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

	// Pipeline flow metrics tracks chunks/results entering each stage,
	// where they are dropped, and where they exit.
	chunksEnteredStage = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "chunks_entered_stage_total",
		Help:      "Total number of chunks (or per-detector work items) entering each pipeline stage.",
	},
		[]string{"stage", "source_type"},
	)

	chunksDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "chunks_dropped_total",
		Help:      "Total number of chunks dropped by pipeline stage and reason.",
	},
		[]string{"stage", "reason", "source_type"},
	)

	resultsProduced = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "results_produced_total",
		Help:      "Total number of raw detector results produced by the detect stage (before filtering).",
	},
		[]string{"detector_name"},
	)

	resultsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "results_dropped_total",
		Help:      "Total number of detector results dropped by pipeline stage and reason.",
	},
		[]string{"stage", "reason", "detector_name"},
	)

	resultsDispatched = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "result_dispatch_attempts_count",
		Help:      "Count of result dispatch attempts.",
	},
		[]string{"detector_name", "verified", "success"},
	)
)
