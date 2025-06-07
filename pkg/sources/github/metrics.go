package github

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	githubNumRateLimitEncountered = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_num_rate_limit_encountered",
		Help:      "Total number of times Github Rate Limit was encountered",
	},
		[]string{"source_name"})

	githubSecondsSpentRateLimited = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_seconds_spent_rate_limited",
		Help:      "Total number of seconds spent idle due to GitHub rate limits.",
	},
		[]string{"source_name"})

	githubReposEnumerated = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_repos_enumerated",
		Help:      "Total number of GitHub repositories enumerated.",
	},
		[]string{"source_name"})

	githubReposScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_repos_scanned",
		Help:      "Total number of GitHub repositories scanned.",
	},
		[]string{"source_name"})

	githubOrgsEnumerated = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_orgs_enumerated",
		Help:      "Total number of GitHub organizations enumerated.",
	},
		[]string{"source_name"})
)
