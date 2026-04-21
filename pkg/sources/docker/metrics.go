package docker

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	dockerLayersScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_layers_scanned",
		Help:      "Total number of Docker layers scanned.",
	},
		[]string{"source_name", "job_id"})

	dockerLayersEnumerated = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "docker_layers_enumerated",
			Help:      "Total number of Docker layers enumerated.",
		},
		[]string{"source_name", "job_id"})

	dockerHistoryEntriesScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_history_entries_scanned",
		Help:      "Total number of Docker image history entries scanned.",
	},
		[]string{"source_name", "job_id"})

	dockerHistoryEntriesEnumerated = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_history_entries_enumerated",
		Help:      "Total number of Docker history entries enumerated.",
	},
		[]string{"source_name", "job_id"})

	dockerImagesScanned = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_images_scanned",
		Help:      "Total number of Docker images scanned.",
	},
		[]string{"source_name", "job_id"})

	dockerImagesEnumerated = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "docker_images_enumerated",
		Help:      "Total number of Docker images enumerated.",
	},
		[]string{"source_name", "job_id"})

	dockerListImagesAPIDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: common.MetricsNamespace,
			Subsystem: common.MetricsSubsystem,
			Name:      "docker_list_images_api_duration_seconds",
			Help:      "Duration of Docker list images API calls.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"source_name"})
)
