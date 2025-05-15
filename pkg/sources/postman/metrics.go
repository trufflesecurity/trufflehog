package postman

import (
	"strconv"

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
		[]string{"source_name", "job_id", "endpoint"})

	postmanAPIMonthlyRequestsRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "postman_api_monthly_requests_remaining",
		Help:      "Total number Postman API requests remaining this month.",
	},
		[]string{"source_name"})
)

func newMetricsFromJob(sourceName string, jobID int) *metrics {
	return &metrics{
		apiRequests: postmanAPIRequestsMetric.MustCurryWith(map[string]string{
			"source_name": sourceName,
			"job_id":      strconv.Itoa(jobID),
		}),
		apiMonthlyRequestsRemaining: postmanAPIMonthlyRequestsRemaining.MustCurryWith(map[string]string{
			"source_name": sourceName,
		}),
	}
}
