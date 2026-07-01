package engine

import (
	"errors"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Channel and worker pool label values exposed by runtimeCollector. These
// names appear in metric labels, so external dashboards depend on them being
// stable.
const (
	channelSourceChunks              = "source_chunks_chan"
	channelDetectableChunks          = "detectable_chunks_chan"
	channelVerificationOverlapChunks = "verification_overlap_chunks_chan"
	channelResults                   = "results_chan"

	workerEngine              = "engine_workers"
	workerDetector            = "detector_workers"
	workerVerificationOverlap = "verification_overlap_workers"
	workerNotifier            = "notifier_workers"
	workerSources             = "source_workers"
)

// runtimeCollector exposes live engine internals (channel queue depths,
// channel capacities, configured worker pool sizes, and aggregate scan
// counters) to Prometheus. Values are sampled lazily on each scrape via
// len/cap and atomic loads, so there is no background goroutine overhead
// between scrapes.
type runtimeCollector struct {
	engine *Engine

	channelSize     *prometheus.Desc
	channelCapacity *prometheus.Desc
	workerCount     *prometheus.Desc
	activeSources   *prometheus.Desc

	bytesScanned           *prometheus.Desc
	chunksScanned          *prometheus.Desc
	verifiedSecretsFound   *prometheus.Desc
	unverifiedSecretsFound *prometheus.Desc
}

// newRuntimeCollector constructs a runtimeCollector bound to the given
// Engine. The metric descriptors are built once here; each subsequent Collect
// call reuses them and only samples fresh values.
func newRuntimeCollector(e *Engine) *runtimeCollector {
	fq := func(name string) string {
		return prometheus.BuildFQName(common.MetricsNamespace, common.MetricsSubsystem, name)
	}
	return &runtimeCollector{
		engine: e,
		channelSize: prometheus.NewDesc(
			fq("engine_channel_size"),
			"Current number of items buffered in an engine channel.",
			[]string{"channel"}, nil,
		),
		channelCapacity: prometheus.NewDesc(
			fq("engine_channel_capacity"),
			"Buffer capacity of an engine channel.",
			[]string{"channel"}, nil,
		),
		workerCount: prometheus.NewDesc(
			fq("engine_worker_count"),
			"Configured number of workers in an engine worker pool.",
			[]string{"worker_type"}, nil,
		),
		activeSources: prometheus.NewDesc(
			fq("engine_active_sources"),
			"Number of sources currently running.",
			nil, nil,
		),
		bytesScanned: prometheus.NewDesc(
			fq("engine_bytes_scanned"),
			"Total bytes scanned by the engine since Start.",
			nil, nil,
		),
		chunksScanned: prometheus.NewDesc(
			fq("engine_chunks_scanned"),
			"Total chunks scanned by the engine since Start.",
			nil, nil,
		),
		verifiedSecretsFound: prometheus.NewDesc(
			fq("engine_verified_secrets_found"),
			"Total verified secrets found by the engine since Start.",
			nil, nil,
		),
		unverifiedSecretsFound: prometheus.NewDesc(
			fq("engine_unverified_secrets_found"),
			"Total unverified secrets found by the engine since Start.",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector by emitting every metric
// descriptor this collector will ever produce. The registry uses these
// descriptors to detect conflicts at registration time.
func (c *runtimeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.channelSize
	ch <- c.channelCapacity
	ch <- c.workerCount
	ch <- c.activeSources
	ch <- c.bytesScanned
	ch <- c.chunksScanned
	ch <- c.verifiedSecretsFound
	ch <- c.unverifiedSecretsFound
}

// Collect implements prometheus.Collector and is invoked by the registry on
// every scrape. It samples the engine's channels via len/cap, reads scan
// counters via atomic.Load, and emits one metric per (descriptor, label set)
// combination.
func (c *runtimeCollector) Collect(ch chan<- prometheus.Metric) {
	e := c.engine

	sourceChunks := e.sourceManager.Chunks()
	channels := []struct {
		name     string
		size     int
		capacity int
	}{
		{channelSourceChunks, len(sourceChunks), cap(sourceChunks)},
		{channelDetectableChunks, len(e.detectableChunksChan), cap(e.detectableChunksChan)},
		{channelVerificationOverlapChunks, len(e.verificationOverlapChunksChan), cap(e.verificationOverlapChunksChan)},
		{channelResults, len(e.results), cap(e.results)},
	}
	for _, q := range channels {
		ch <- prometheus.MustNewConstMetric(c.channelSize, prometheus.GaugeValue, float64(q.size), q.name)
		ch <- prometheus.MustNewConstMetric(c.channelCapacity, prometheus.GaugeValue, float64(q.capacity), q.name)
	}

	workers := []struct {
		name  string
		count int
	}{
		{workerEngine, e.concurrency},
		{workerDetector, e.concurrency * e.detectorWorkerMultiplier},
		{workerVerificationOverlap, e.concurrency * e.verificationOverlapWorkerMultiplier},
		{workerNotifier, e.concurrency * e.notificationWorkerMultiplier},
		// SourceManager treats its concurrency limit as a semaphore rather than a
		// fixed worker pool, but reporting it here lets dashboards ratio it against
		// activeSources to spot source-side saturation.
		{workerSources, e.sourceManager.MaxConcurrentSources()},
	}
	for _, w := range workers {
		ch <- prometheus.MustNewConstMetric(c.workerCount, prometheus.GaugeValue, float64(w.count), w.name)
	}

	ch <- prometheus.MustNewConstMetric(
		c.activeSources, prometheus.GaugeValue,
		float64(e.sourceManager.ConcurrentSources()),
	)

	// Scan counters are written via atomic.AddUint64 on runtimeMetrics; read
	// them with atomic.LoadUint64 to stay cheap on scrape and avoid the RW mutex.
	m := &e.metrics.Metrics
	ch <- prometheus.MustNewConstMetric(c.bytesScanned, prometheus.CounterValue, float64(atomic.LoadUint64(&m.BytesScanned)))
	ch <- prometheus.MustNewConstMetric(c.chunksScanned, prometheus.CounterValue, float64(atomic.LoadUint64(&m.ChunksScanned)))
	ch <- prometheus.MustNewConstMetric(c.verifiedSecretsFound, prometheus.CounterValue, float64(atomic.LoadUint64(&m.VerifiedSecretsFound)))
	ch <- prometheus.MustNewConstMetric(c.unverifiedSecretsFound, prometheus.CounterValue, float64(atomic.LoadUint64(&m.UnverifiedSecretsFound)))
}

// registerRuntimeMetrics installs the engine's runtime collector into the
// default Prometheus registry. If a collector with identical descriptors is
// already registered (e.g. a previous engine in the same process that didn't
// call Finish), the stale collector is evicted and replaced. Without eviction
// the stale collector would pin a dead engine in memory and permanently block
// future engines from exposing metrics.
func (e *Engine) registerRuntimeMetrics(ctx context.Context) {
	collector := newRuntimeCollector(e)
	err := prometheus.DefaultRegisterer.Register(collector)
	if err != nil {
		var already prometheus.AlreadyRegisteredError
		if !errors.As(err, &already) {
			ctx.Logger().Error(err, "failed to register engine runtime metrics")
			return
		}
		ctx.Logger().V(2).Info("evicting stale engine runtime metrics collector")
		prometheus.DefaultRegisterer.Unregister(already.ExistingCollector)
		if err := prometheus.DefaultRegisterer.Register(collector); err != nil {
			ctx.Logger().Error(err, "failed to register engine runtime metrics after eviction")
			return
		}
	}
	e.runtimeCollector = collector
}

// unregisterRuntimeMetrics removes the engine's runtime collector from the
// default Prometheus registry. Safe to call when registration was skipped.
func (e *Engine) unregisterRuntimeMetrics() {
	if e.runtimeCollector == nil {
		return
	}
	prometheus.DefaultRegisterer.Unregister(e.runtimeCollector)
	e.runtimeCollector = nil
}
