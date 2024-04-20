package sources

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	hooksExecTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "hooks_exec_time_ms",
		Help:      "Time spent executing hooks (ms)",
		Buckets:   []float64{5, 50, 500, 1000},
	}, nil)

	hooksChannelSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "hooks_channel_size",
		Help:      "Total number of metrics waiting in the finished channel.",
	}, nil)
)
