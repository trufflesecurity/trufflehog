package report

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	hooksChannelSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "hooks_channel_size",
		Help:      "Total number of metrics waiting in the finished channel.",
	}, nil)
)
