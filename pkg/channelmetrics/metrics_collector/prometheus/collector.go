package prometheus

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MetricsCollector implements the |channelmetrics.MetricsCollector| interface using Prometheus.
// It records various metrics related to channel operations.
type MetricsCollector struct {
	produceDuration prometheus.Histogram
	consumeDuration prometheus.Histogram
	channelLen      prometheus.Gauge
	channelCap      prometheus.Gauge
}

var (
	collectors   = make(map[string]*MetricsCollector)
	collectorsMu sync.Mutex
)

// NewMetricsCollector creates a new MetricsCollector with
// histograms for produce and consume durations, and gauges for channel length and capacity.
// It accepts namespace, subsystem, and chanName parameters to organize metrics.
// The function initializes and returns a pointer to a MetricsCollector struct
// that contains the following Prometheus metrics:
//
//   - produceDuration: a Histogram metric that measures the duration of producing an item.
//     It tracks the time taken to add an item to the ObservableChan.
//     This metric helps to monitor the performance and latency of item production.
//
//   - consumeDuration: a Histogram metric that measures the duration of consuming an item.
//     It tracks the time taken to retrieve an item from the ObservableChan.
//     This metric helps to monitor the performance and latency of item consumption.
//
//   - channelLen: a Gauge metric that measures the current size of the channel buffer.
//     It tracks the number of items in the channel buffer at any given time.
//     This metric helps to monitor the utilization of the channel buffer.
//
//   - channelCap: a Gauge metric that measures the capacity of the channel buffer.
//     It tracks the maximum number of items that the channel buffer can hold.
//     This metric helps to understand the configuration and potential limits of the channel buffer.
//
// These metrics are useful for monitoring the performance and throughput of the ObservableChan.
// By tracking the durations of item production and consumption, as well as the buffer size and capacity,
// you can identify bottlenecks, optimize performance, and ensure that the ObservableChan is operating efficiently.
func NewMetricsCollector(chanName, namespace, subsystem string) *MetricsCollector {
	key := fmt.Sprintf("%s_%s_%s", namespace, subsystem, chanName)

	collectorsMu.Lock()
	defer collectorsMu.Unlock()

	if collector, exists := collectors[key]; exists {
		return collector
	}

	collector := &MetricsCollector{
		produceDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:      metricName(chanName, "produce_duration_microseconds"),
			Namespace: namespace,
			Subsystem: subsystem,
			Help:      "Duration of producing an item in microseconds.",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 20),
		}),
		consumeDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:      metricName(chanName, "consume_duration_microseconds"),
			Namespace: namespace,
			Subsystem: subsystem,
			Help:      "Duration of consuming an item in microseconds.",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 20),
		}),
		channelLen: promauto.NewGauge(prometheus.GaugeOpts{
			Name:      metricName(chanName, "channel_length"),
			Namespace: namespace,
			Subsystem: subsystem,
			Help:      "Current size of the channel buffer.",
		}),
		channelCap: promauto.NewGauge(prometheus.GaugeOpts{
			Name:      metricName(chanName, "channel_capacity"),
			Namespace: namespace,
			Subsystem: subsystem,
			Help:      "Capacity of the channel buffer.",
		}),
	}

	collectors[key] = collector
	return collector
}

// metricName constructs a full metric name by combining the channel name with the specific metric.
func metricName(chanName, metric string) string { return chanName + "_" + metric }

// RecordProduceDuration records the duration taken to produce an item into the channel.
func (c *MetricsCollector) RecordProduceDuration(duration time.Duration) {
	c.produceDuration.Observe(float64(duration.Microseconds()))
}

// RecordConsumeDuration records the duration taken to consume an item from the channel.
func (c *MetricsCollector) RecordConsumeDuration(duration time.Duration) {
	c.consumeDuration.Observe(float64(duration.Microseconds()))
}

// RecordChannelLen records the current size of the channel buffer.
func (c *MetricsCollector) RecordChannelLen(size int) { c.channelLen.Set(float64(size)) }

// RecordChannelCap records the capacity of the channel buffer.
func (c *MetricsCollector) RecordChannelCap(capacity int) { c.channelCap.Set(float64(capacity)) }
