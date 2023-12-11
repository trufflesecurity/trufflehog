package gitlab

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	gitlabReposEnumerated = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "gitlab_repos_enumerated",
		Help:      "Total number of Gitlab repositories enumerated.",
	},
		[]string{"source_name"})

	gitlabReposScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "gitlab_repos_scanned",
		Help:      "Total number of Gitlab repositories scanned.",
	},
		[]string{"source_name"})
)
