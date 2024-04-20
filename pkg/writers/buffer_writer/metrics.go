package bufferwriter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var (
	totalWriteSize = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "buffer_writer_total_write_size_bytes",
		Help:      "Total size of data written by the BufferWriter in bytes.",
	})

	totalWriteDuration = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: common.MetricsNamespace,
		Subsystem: common.MetricsSubsystem,
		Name:      "buffer_writer_total_write_duration_microseconds",
		Help:      "Total duration of write operations by the BufferWriter in microseconds.",
	})
)
