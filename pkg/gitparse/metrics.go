package gitparse

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	produceDiffDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:      "produce_diff_duration_microseconds",
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Help:      "Duration of producing a diff.",
		Buckets:   prometheus.ExponentialBuckets(1, 10, 8),
	})

	consumeDiffDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:      "consume_diff_duration_microseconds",
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Help:      "Duration of consuming a diff.",
		Buckets:   prometheus.ExponentialBuckets(1, 10, 8),
	})

	diffWaitingTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:      "diff_waiting_time_microseconds",
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Help:      "Waiting time of a diff in the queue.",
		Buckets:   prometheus.ExponentialBuckets(1, 10, 8),
	})
)

type metrics struct {
	produceDiffDuration prometheus.Histogram
	consumeDiffDuration prometheus.Histogram
	diffWaitingTime     prometheus.Histogram
}

// newDiffChanMetrics creates a new metrics instance configured with Prometheus metrics specific to a DiffChan.
// The function initializes and returns a pointer to a DiffChanMetrics struct that contains the following Prometheus metrics:
//
//   - produceDiffDuration: a Histogram metric that measures the duration of producing a diff.
//     It tracks the time taken to add a diff to the DiffChan.
//     This metric helps to monitor the performance and latency of diff production.
//
//   - consumeDiffDuration: a Histogram metric that measures the duration of consuming a diff.
//     It tracks the time taken to retrieve a diff from the DiffChan.
//     This metric helps to monitor the performance and latency of diff consumption.
//
//   - diffWaitingTime: a Histogram metric that measures the waiting time of a diff in the queue.
//     It tracks the time a diff spends waiting in the queue before being processed.
//     This metric helps to monitor the queuing time and identify any bottlenecks or delays in diff processing.
//
// These metrics are useful for monitoring the performance and throughput of the DiffChan.
// By tracking the durations of diff production and consumption, as well as the total counts,
// you can identify bottlenecks, optimize performance, and ensure that the DiffChan is operating efficiently.
//
// The metrics are created with a common namespace and subsystem defined in the metrics package.
// This helps to organize and group related metrics together.
func newDiffChanMetrics() *metrics {
	return &metrics{
		produceDiffDuration: produceDiffDuration,
		consumeDiffDuration: consumeDiffDuration,
		diffWaitingTime:     diffWaitingTime,
	}
}

func (m *metrics) observeProduceDiffDuration(duration float64) {
	m.produceDiffDuration.Observe(duration)
}

func (m *metrics) observeConsumeDiffDuration(duration float64) {
	m.consumeDiffDuration.Observe(duration)
}

func (m *metrics) observeDiffWaitingTime(duration float64) {
	m.diffWaitingTime.Observe(duration)
}
