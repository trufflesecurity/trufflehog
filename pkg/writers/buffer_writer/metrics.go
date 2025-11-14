package bufferwriter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	writeSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "buffer_writer_write_size_bytes",
		Help:      "Total size of data written by the BufferWriter in bytes.",
		Buckets:   prometheus.ExponentialBuckets(100, 10, 7),
	})

	totalWriteDuration = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystemScanner,
		Name:      "buffer_writer_total_write_duration_microseconds",
		Help:      "Total duration of write operations by the BufferWriter in microseconds.",
	})
)
