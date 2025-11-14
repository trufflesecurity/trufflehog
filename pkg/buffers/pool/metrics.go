package pool

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	activeBufferCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "active_buffer_count",
		Help:      "Current number of active buffers.",
	})

	bufferCount = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "buffer_count",
		Help:      "Total number of buffers managed by the pool.",
	})

	shrinkCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "shrink_count",
		Help:      "Total number of times buffers in the pool have shrunk.",
	})

	shrinkAmount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "shrink_amount",
		Help:      "Total amount of bytes buffers in the pool have shrunk by.",
	})

	checkoutCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "checkout_count",
		Help:      "Total number of Buffer checkouts.",
	})
)
