package buffer

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	growCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "grow_count",
		Help:      "Total number of times buffers in the pool have grown.",
	})

	growAmount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "grow_amount",
		Help:      "Total amount of bytes buffers in the pool have grown by.",
	})

	checkoutDurationTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "checkout_duration_total_us",
		Help:      "Total duration in microseconds of Buffer checkouts.",
	})

	checkoutDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "checkout_duration_us",
		Help:      "Duration in microseconds of Buffer checkouts.",
		Buckets:   prometheus.ExponentialBuckets(10, 10, 7),
	})

	totalBufferLength = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "total_buffer_length",
		Help:      "Total length of all buffers combined.",
	})

	totalBufferSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "total_buffer_size",
		Help:      "Total size of all buffers combined.",
	})
)
