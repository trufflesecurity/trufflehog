package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	reportGenerationTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "report_generation_total",
		Help:      "Total number of report generation attempts",
	})

	reportGenerationErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "report_generation_errors",
		Help:      "Total number of errors encountered during report generation, by error type",
	},
		[]string{"error_type"},
	)

	unitMetricsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "unit_metrics_total",
		Help:      "Total number of UnitMetrics generated, by unit type",
	},
		[]string{"unit_type"},
	)

	unitMetricsWithErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "unit_metrics_with_errors_total",
		Help:      "Total number of UnitMetrics containing errors, by unit type",
	},
		[]string{"unit_type"},
	)

	reportFileSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "report_file_size_bytes",
		Help:      "Size of the generated report file in bytes",
	})

	reportGenerationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "report_generation_duration_seconds",
		Help:      "Time taken to generate a report",
		Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10),
	})
)
