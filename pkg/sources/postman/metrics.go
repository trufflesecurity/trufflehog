package postman

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type metrics struct {
	apiRequests                 *prometheus.CounterVec
	apiMonthlyRequestsRemaining *prometheus.GaugeVec
}

var (
	postmanAPIRequestsMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "postman_api_requests",
		Help:      "Total number of API requests made to Postman.",
	},
		[]string{"source_name", "endpoint"})

	postmanAPIMonthlyRequestsRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "postman_api_monthly_requests_remaining",
		Help:      "Total number Postman API requests remaining this month.",
	},
		[]string{"source_name"})
)

func newMetrics(sourceName string) *metrics {
	return &metrics{
		apiRequests: postmanAPIRequestsMetric.MustCurryWith(map[string]string{
			"source_name": sourceName,
		}),
		apiMonthlyRequestsRemaining: postmanAPIMonthlyRequestsRemaining.MustCurryWith(map[string]string{
			"source_name": sourceName,
		}),
	}
}
