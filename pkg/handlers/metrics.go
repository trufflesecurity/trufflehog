package handlers

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type metrics struct {
	handlerType            handlerType
	handleFileLatency      *prometheus.HistogramVec
	bytesProcessed         *prometheus.CounterVec
	filesProcessed         *prometheus.CounterVec
	errorsEncountered      *prometheus.CounterVec
	filesSkipped           *prometheus.CounterVec
	maxArchiveDepthCount   *prometheus.CounterVec
	fileSize               *prometheus.HistogramVec
	fileProcessingTimeouts *prometheus.CounterVec
}

var (
	handleFileLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_file_latency_milliseconds",
			Help:      "Latency of the HandleFile method",
			Buckets:   prometheus.ExponentialBuckets(1, 5, 6),
		},
		[]string{"handler_type"},
	)
	bytesProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_bytes_processed_total",
			Help:      "Total number of bytes processed",
		},
		[]string{"handler_type"},
	)
	filesProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_files_processed_total",
			Help:      "Total number of files processed",
		},
		[]string{"handler_type"},
	)
	errorsEncountered = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_errors_encountered_total",
			Help:      "Total number of errors encountered",
		},
		[]string{"handler_type"},
	)
	filesSkipped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_files_skipped_total",
			Help:      "Total number of files skipped",
		},
		[]string{"handler_type"},
	)
	maxArchiveDepthCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_max_archive_depth_reached_total",
			Help:      "Total number of times the maximum archive depth was reached",
		},
		[]string{"handler_type"},
	)
	fileSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_file_size_bytes",
			Help:      "Sizes of files handled by the handler",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 4),
		},
		[]string{"handler_type"},
	)
	fileProcessingTimeouts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystemScanner,
			Name:      "handlers_file_processing_timeouts_total",
			Help:      "Total number of file processing timeouts encountered",
		},
		[]string{"handler_type"},
	)
)

// newHandlerMetrics creates a new metrics instance configured with Prometheus metrics specific to a file handler.
// The function takes a handlerType parameter, which represents the type of the handler (e.g., "default", "ar", "rpm").
// The handlerType is used as a label for each metric, allowing for differentiation and aggregation of metrics
// based on the handler type.
//
// The function initializes and returns a pointer to a metrics struct that contains the following Prometheus metrics:
//
//   - handleFileLatency: a HistogramVec metric that measures the latency of the HandleFile method.
//     It uses exponential buckets with a base of 1 and a factor of 5, up to 6 buckets.
//     The metric is labeled with the handlerType.
//
//   - bytesProcessed: a CounterVec metric that tracks the total number of bytes processed by the handler.
//     It is labeled with the handlerType.
//
//   - filesProcessed: a CounterVec metric that tracks the total number of files processed by the handler.
//     It is labeled with the handlerType.
//
//   - errorsEncountered: a CounterVec metric that tracks the total number of errors encountered by the handler.
//     It is labeled with the handlerType.
//
//   - filesSkipped: a CounterVec metric that tracks the total number of files skipped by the handler.
//     It is labeled with the handlerType.
//
//   - maxArchiveDepthCount: a CounterVec metric that tracks the total number of times the maximum archive depth was reached.
//     It is labeled with the handlerType.
//
//   - fileSize: a HistogramVec metric that measures the sizes of files handled by the handler.
//     It uses exponential buckets with a base of 1 and a factor of 2, up to 4 buckets.
//     It is labeled with the handlerType.
//
//   - fileProcessingTimeouts: a CounterVec metric that tracks the total number of file processing timeouts
//     encountered by the handler.
//     It is labeled with the handlerType.
//
// The metrics are created with a common namespace and subsystem defined in the common package.
// This helps to organize and group related metrics together.
//
// By initializing the metrics with the handlerType label, the function enables accurate attribution and aggregation
// of metrics based on the specific handler type. This allows for fine-grained monitoring and analysis of
// file handler performance.
func newHandlerMetrics(t handlerType) *metrics {
	return &metrics{
		handlerType:            t,
		handleFileLatency:      handleFileLatency,
		bytesProcessed:         bytesProcessed,
		filesProcessed:         filesProcessed,
		errorsEncountered:      errorsEncountered,
		filesSkipped:           filesSkipped,
		maxArchiveDepthCount:   maxArchiveDepthCount,
		fileSize:               fileSize,
		fileProcessingTimeouts: fileProcessingTimeouts,
	}
}

func (m *metrics) observeHandleFileLatency(duration int64) {
	m.handleFileLatency.WithLabelValues(string(m.handlerType)).Observe(float64(duration))
}

func (m *metrics) incBytesProcessed(bytes int) {
	m.bytesProcessed.WithLabelValues(string(m.handlerType)).Add(float64(bytes))
}

func (m *metrics) incFilesProcessed() {
	m.filesProcessed.WithLabelValues(string(m.handlerType)).Inc()
}

func (m *metrics) incErrors() {
	m.errorsEncountered.WithLabelValues(string(m.handlerType)).Inc()
}

func (m *metrics) incFilesSkipped() {
	m.filesSkipped.WithLabelValues(string(m.handlerType)).Inc()
}

func (m *metrics) incMaxArchiveDepthCount() {
	m.maxArchiveDepthCount.WithLabelValues(string(m.handlerType)).Inc()
}

func (m *metrics) observeFileSize(size int64) {
	m.fileSize.WithLabelValues(string(m.handlerType)).Observe(float64(size))
}

func (m *metrics) incFileProcessingTimeouts() {
	m.fileProcessingTimeouts.WithLabelValues(string(m.handlerType)).Inc()
}
