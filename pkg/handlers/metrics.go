package handlers

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type metrics struct {
	handlerType       handlerType
	handleFileLatency *prometheus.HistogramVec
	bytesProcessed    *prometheus.CounterVec
	filesProcessed    *prometheus.CounterVec
	errorsEncountered *prometheus.CounterVec
}

func newHandlerMetrics(t handlerType) *metrics {
	return &metrics{
		handlerType: t,
		handleFileLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "handle_file_latency_microseconds",
				Help:      "Latency of the HandleFile method",
				Buckets:   prometheus.ExponentialBuckets(1, 2, 5),
			},
			[]string{"handlerType"},
		),
		bytesProcessed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "bytes_processed_total",
				Help:      "Total number of bytes processed",
			},
			[]string{"handlerType"},
		),
		filesProcessed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "files_processed_total",
				Help:      "Total number of files processed",
			},
			[]string{"handlerType"},
		),
		errorsEncountered: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: common.MetricsNamespace,
				Subsystem: common.MetricsSubsystem,
				Name:      "errors_encountered_total",
				Help:      "Total number of errors encountered",
			},
			[]string{"handlerType"},
		),
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

<<<<<<< HEAD
func (m *metrics) incErrors() {
=======
func (m *metrics) incErrorsEncountered() {
>>>>>>> 2c8fba4cf (add metrics for file handling)
	m.errorsEncountered.WithLabelValues(string(m.handlerType)).Inc()
}
