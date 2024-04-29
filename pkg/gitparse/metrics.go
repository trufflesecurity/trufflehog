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

	producedDiffsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name:      "produced_diffs_total",
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Help:      "Total number of produced diffs.",
	})

	consumedDiffsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name:      "consumed_diffs_total",
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Help:      "Total number of consumed diffs.",
	})
)

type metrics struct {
	produceDiffDuration prometheus.Histogram
	consumeDiffDuration prometheus.Histogram
	producedDiffsTotal  prometheus.Counter
	consumedDiffsTotal  prometheus.Counter
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
//   - producedDiffsTotal: a Counter metric that tracks the total number of diffs produced.
//     It increments each time a diff is successfully added to the DiffChan.
//     This metric provides insights into the overall volume of diffs being produced.
//
//   - consumedDiffsTotal: a Counter metric that tracks the total number of diffs consumed.
//     It increments each time a diff is successfully retrieved from the DiffChan.
//     This metric provides insights into the overall volume of diffs being consumed.
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
		producedDiffsTotal:  producedDiffsTotal,
		consumedDiffsTotal:  consumedDiffsTotal,
	}
}

func (m *metrics) observeProduceDiffDuration(duration float64) {
	m.produceDiffDuration.Observe(duration)
}

func (m *metrics) observeConsumeDiffDuration(duration float64) {
	m.consumeDiffDuration.Observe(duration)
}

func (m *metrics) incProducedDiffsTotal() { m.producedDiffsTotal.Inc() }

func (m *metrics) incConsumedDiffsTotal() { m.consumedDiffsTotal.Inc() }
