package buffer

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	activeBufferCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "active_buffer_count",
		Help:      "Current number of active buffers.",
	})

	bufferCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "buffer_count",
		Help:      "Total number of buffers managed by the pool.",
	})

	totalBufferLength = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "total_buffer_length",
		Help:      "Total length of all buffers combined.",
	})

	totalBufferSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "total_buffer_size",
		Help:      "Total size of all buffers combined.",
	})

	growCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "grow_count",
		Help:      "Total number of times buffers in the pool have grown.",
	})

	growAmount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "grow_amount",
		Help:      "Total amount of bytes buffers in the pool have grown by.",
	})

	shrinkCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "shrink_count",
		Help:      "Total number of times buffers in the pool have shrunk.",
	})

	shrinkAmount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "shrink_amount",
		Help:      "Total amount of bytes buffers in the pool have shrunk by.",
	})

	checkoutDurationTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "checkout_duration_total_us",
		Help:      "Total duration in microseconds of Buffer checkouts.",
	})

	checkoutDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "checkout_duration_us",
		Help:      "Duration in microseconds of Buffer checkouts.",
		Buckets:   []float64{50, 500, 5000},
	})

	checkoutCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "checkout_count",
		Help:      "Total number of Buffer checkouts.",
	})
)
