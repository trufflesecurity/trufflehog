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

	githubDanglingCommitsEnumerated = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_dangling_commits_enumerated",
		Help:      "Total number of GitHub dangling commits enumerated.",
	}, []string{"repo_name"})

	githubDanglingCommitsClonedOk = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_dangling_commits_cloned_ok",
		Help:      "Total number of GitHub dangling commits successfully retrieved.",
	}, []string{"repo_name"})

	githubDanglingCommitsClonedNotFound = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_dangling_commits_cloned_not_found",
		Help:      "Total number of GitHub dangling commits that no longer exist in the remote.",
	}, []string{"repo_name"})

	githubDanglingCommitsClonedErr = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "github_dangling_commits_cloned_err",
		Help:      "Total number of GitHub dangling commits unsuccessfully retrieved.",
	}, []string{"repo_name"})
)
