package bufferedfilewriter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	totalWriteSize = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "buffered_file_writer_total_write_size_bytes",
		Help:      "Total size of data written by the BufferedFileWriter in bytes.",
	})

	totalWriteDuration = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "buffered_file_writer_total_write_duration_microseconds",
		Help:      "Total duration of write operations by the BufferedFileWriter in microseconds.",
	})

	diskWriteCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "disk_write_count",
		Help:      "Total number of times data was written to disk by the BufferedFileWriter.",
	})

	fileSizeHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "file_size_bytes",
		Help:      "Sizes of files created by the BufferedFileWriter.",
		Buckets:   prometheus.ExponentialBuckets(defaultThreshold, 2, 4),
	})
)
