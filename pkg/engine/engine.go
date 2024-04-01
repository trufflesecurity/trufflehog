package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	lru "github.com/hashicorp/golang-lru/v2"
	"google.golang.org/protobuf/proto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

var overlapError = errors.New("More than one detector has found this result. For your safety, verification has been disabled. You can override this behavior by using the --allow-verification-overlap flag.")

// Metrics for the scan engine for external consumption.
type Metrics struct {
	BytesScanned           uint64
	ChunksScanned          uint64
	VerifiedSecretsFound   uint64
	UnverifiedSecretsFound uint64
	AvgDetectorTime        map[string]time.Duration

	scanStartTime time.Time
	ScanDuration  time.Duration
}

// runtimeMetrics for the scan engine for internal use by the engine.
type runtimeMetrics struct {
	mu sync.RWMutex
	Metrics
	detectorAvgTime sync.Map
}

// Printer is used to format found results and output them to the user. Ex JSON, plain text, etc.
// Please note printer implementations SHOULD BE thread safe.
type Printer interface {
	Print(ctx context.Context, r *detectors.ResultWithMetadata) error
}

type Engine struct {
	// CLI flags.
	concurrency     int
	decoders        []decoders.Decoder
	detectors       []detectors.Detector
	jobReportWriter io.WriteCloser
	// filterUnverified is used to reduce the number of unverified results.
	// If there are multiple unverified results for the same chunk for the same detector,
	// only the first one will be kept.
	filterUnverified bool
	// entropyFilter is used to filter out unverified results using Shannon entropy.
	filterEntropy           *float64
	notifyVerifiedResults   bool
	notifyUnverifiedResults bool
	notifyUnknownResults    bool
	verificationOverlap     bool
	printAvgDetectorTime    bool

	// ahoCorasickHandler manages the Aho-Corasick trie and related keyword lookups.
	ahoCorasickCore *ahocorasick.AhoCorasickCore

	// Engine synchronization primitives.
	sourceManager                 *sources.SourceManager
	results                       chan detectors.ResultWithMetadata
	detectableChunksChan          chan detectableChunk
	verificationOverlapChunksChan chan verificationOverlapChunk
	workersWg                     sync.WaitGroup
	verificationOverlapWg         sync.WaitGroup
	wgDetectorWorkers             sync.WaitGroup
	WgNotifier                    sync.WaitGroup

	// Runtime information.
	metrics runtimeMetrics
	// numFoundResults is used to keep track of the number of results found.
	numFoundResults uint32

	// printer provides a method for formatting and outputting search results.
	// The specific implementation (e.g., JSON, plain text)
	// should be set during initialization based on user preference or program requirements.
	printer Printer

	// dedupeCache is used to deduplicate results by comparing the
	// detector type, raw result, and source metadata
	dedupeCache *lru.Cache[string, detectorspb.DecoderType]

	// verify determines whether the scanner will attempt to verify candidate secrets
	verify bool

	// Note: bad hack only used for testing
	verificationOverlapTracker *verificationOverlapTracker
}

type verificationOverlapTracker struct {
	verificationOverlapDuplicateCount int
	mu                                sync.Mutex
}

func (r *verificationOverlapTracker) increment() {
	r.mu.Lock()
	r.verificationOverlapDuplicateCount++
	r.mu.Unlock()
}

// Option is used to configure the engine during initialization using functional options.
type Option func(*Engine)

func WithJobReportWriter(w io.WriteCloser) Option {
	return func(e *Engine) {
		e.jobReportWriter = w
	}
}

func WithConcurrency(concurrency int) Option {
	return func(e *Engine) {
		e.concurrency = concurrency
	}
}

const ignoreTag = "trufflehog:ignore"

func WithDetectors(d ...detectors.Detector) Option {
	return func(e *Engine) {
		e.detectors = append(e.detectors, d...)
	}
}

func WithDecoders(decoders ...decoders.Decoder) Option {
	return func(e *Engine) {
		e.decoders = decoders
	}
}

// WithFilterUnverified sets the filterUnverified flag on the engine. If set to
// true, the engine will only return the first unverified result for a chunk for a detector.
func WithFilterUnverified(filter bool) Option {
	return func(e *Engine) {
		e.filterUnverified = filter
	}
}

// WithFilterEntropy filters out unverified results using Shannon entropy.
func WithFilterEntropy(entropy float64) Option {
	return func(e *Engine) {
		if entropy > 0 {
			e.filterEntropy = &entropy
		}
	}
}

// WithResults defines which results will be printed by the engine.
func WithResults(results map[string]struct{}) Option {
	return func(e *Engine) {
		if len(results) == 0 {
			return
		}

		_, ok := results["verified"]
		e.notifyVerifiedResults = ok

		_, ok = results["unknown"]
		e.notifyUnknownResults = ok

		_, ok = results["unverified"]
		e.notifyUnverifiedResults = ok
	}
}

// WithPrintAvgDetectorTime sets the printAvgDetectorTime flag on the engine. If set to
// true, the engine will print the average time taken by each detector.
// This option allows us to measure the time taken for each detector ONLY if
// the engine is configured to print the results.
// Calculating the average time taken by each detector is an expensive operation
// and should be avoided unless specified by the user.
func WithPrintAvgDetectorTime(printAvgDetectorTime bool) Option {
	return func(e *Engine) {
		e.printAvgDetectorTime = printAvgDetectorTime
	}
}

// WithFilterDetectors applies a filter to the configured list of detectors. If
// the filterFunc returns true, the detector will be included for scanning.
// This option applies to the existing list of detectors configured, so the
// order this option appears matters. All filtering happens before scanning.
func WithFilterDetectors(filterFunc func(detectors.Detector) bool) Option {
	return func(e *Engine) {
		// If no detectors are configured, do nothing.
		if e.detectors == nil {
			return
		}
		e.detectors = filterDetectors(filterFunc, e.detectors)
	}
}

// WithPrinter sets the Printer on the engine.
func WithPrinter(printer Printer) Option {
	return func(e *Engine) {
		e.printer = printer
	}
}

// WithVerify configures whether the scanner will verify candidate secrets.
func WithVerify(verify bool) Option {
	return func(e *Engine) {
		e.verify = verify
	}
}

func withVerificationOverlapTracking() Option {
	return func(e *Engine) {
		e.verificationOverlapTracker = &verificationOverlapTracker{
			verificationOverlapDuplicateCount: 0,
		}
	}
}

// WithVerificationOverlap
func WithVerificationOverlap(verificationOverlap bool) Option {
	return func(e *Engine) {
		e.verificationOverlap = verificationOverlap
	}
}

func filterDetectors(filterFunc func(detectors.Detector) bool, input []detectors.Detector) []detectors.Detector {
	var out []detectors.Detector
	for _, detector := range input {
		if filterFunc(detector) {
			out = append(out, detector)
		}
	}
	return out
}

// HasFoundResults returns true if any results are found.
func (e *Engine) HasFoundResults() bool {
	return atomic.LoadUint32(&e.numFoundResults) > 0
}

// GetMetrics returns a copy of Metrics.
// It's safe for concurrent use, and the caller can't modify the original data.
func (e *Engine) GetMetrics() Metrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	result := e.metrics.Metrics
	result.AvgDetectorTime = make(map[string]time.Duration, len(e.metrics.AvgDetectorTime))

	for detectorName, durations := range e.DetectorAvgTime() {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(len(durations))
		result.AvgDetectorTime[detectorName] = avgDuration
	}

	result.ScanDuration = e.metrics.getScanDuration()

	return result
}

// GetDetectorsMetrics returns a copy of the average time taken by each detector.
func (e *Engine) GetDetectorsMetrics() map[string]time.Duration {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	result := make(map[string]time.Duration, len(DefaultDetectors()))
	for detectorName, durations := range e.DetectorAvgTime() {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avgDuration := total / time.Duration(len(durations))
		result[detectorName] = avgDuration
	}

	return result
}

// getScanDuration returns the duration of the scan.
// If the scan is still running, it returns the time since the scan started.
func (m *Metrics) getScanDuration() time.Duration {
	if m.ScanDuration == 0 {
		return time.Since(m.scanStartTime)
	}

	return m.ScanDuration
}

// DetectorAvgTime returns the average time taken by each detector.
func (e *Engine) DetectorAvgTime() map[string][]time.Duration {
	logger := context.Background().Logger()
	avgTime := map[string][]time.Duration{}
	e.metrics.detectorAvgTime.Range(func(k, v any) bool {
		key, ok := k.(string)
		if !ok {
			logger.Info("expected detectorAvgTime key to be a string")
			return true
		}

		value, ok := v.([]time.Duration)
		if !ok {
			logger.Info("expected detectorAvgTime value to be []time.Duration")
			return true
		}
		avgTime[key] = value
		return true
	})
	return avgTime
}

// Start initializes and activates the engine's processing pipeline.
// It sets up various default configurations, prepares lookup structures for
// detectors, conducts basic sanity checks, and kickstarts all necessary workers.
// Once started, the engine begins processing input data to identify secrets.
func Start(ctx context.Context, options ...Option) (*Engine, error) {
	e := &Engine{}

	if err := e.initialize(ctx, options...); err != nil {
		return nil, err
	}
	e.initSourceManager(ctx)
	e.setDefaults(ctx)
	e.sanityChecks(ctx)
	e.startWorkers(ctx)

	return e, nil
}

var defaultChannelBuffer = runtime.NumCPU()

// initialize prepares the engine's internal structures. The LRU cache optimizes
// deduplication efforts, allowing the engine to quickly check if a chunk has
// been processed before, thereby saving computational overhead.
func (e *Engine) initialize(ctx context.Context, options ...Option) error {
	// TODO (ahrav): Determine the optimal cache size.
	const cacheSize = 512 // number of entries in the LRU cache

	cache, err := lru.New[string, detectorspb.DecoderType](cacheSize)
	if err != nil {
		return fmt.Errorf("failed to initialize LRU cache: %w", err)
	}
	const (
		// detectableChunksChanMultiplier is set to accommodate a high number of concurrent worker goroutines.
		// This multiplier ensures that the detectableChunksChan channel has sufficient buffer capacity
		// to hold messages from multiple worker groups (detector workers/ verificationOverlap workers) without blocking.
		// A large buffer helps accommodate for the fact workers are producing data at a faster rate
		// than it can be consumed.
		detectableChunksChanMultiplier = 50
		// verificationOverlapChunksChanMultiplier uses a smaller buffer compared to detectableChunksChanMultiplier.
		// This reflects the anticipated lower volume of data that needs re-verification.
		// The buffer size is a trade-off between memory usage and the need to prevent blocking.
		verificationOverlapChunksChanMultiplier = 25
	)

	// Channels are used for communication between different parts of the engine,
	// ensuring that data flows smoothly without race conditions.
	// The buffer sizes for these channels are set to multiples of defaultChannelBuffer,
	// considering the expected concurrency and workload in the system.
	e.detectableChunksChan = make(chan detectableChunk, defaultChannelBuffer*detectableChunksChanMultiplier)
	e.notifyVerifiedResults = true
	e.notifyUnknownResults = true
	e.notifyUnverifiedResults = true
	e.verificationOverlapChunksChan = make(chan verificationOverlapChunk, defaultChannelBuffer*verificationOverlapChunksChanMultiplier)
	e.results = make(chan detectors.ResultWithMetadata, defaultChannelBuffer)
	e.dedupeCache = cache
	e.printer = new(output.PlainPrinter)
	e.metrics = runtimeMetrics{Metrics: Metrics{scanStartTime: time.Now()}}

	for _, option := range options {
		option(e)
	}
	ctx.Logger().V(4).Info("engine initialized")

	ctx.Logger().V(4).Info("setting up aho-corasick core")
	e.ahoCorasickCore = ahocorasick.NewAhoCorasickCore(e.detectors)
	ctx.Logger().V(4).Info("set up aho-corasick core")

	return nil
}

func (e *Engine) initSourceManager(ctx context.Context) {
	opts := []func(*sources.SourceManager){
		sources.WithConcurrentSources(int(e.concurrency)),
		sources.WithConcurrentUnits(int(e.concurrency)),
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultChannelBuffer),
	}
	if e.jobReportWriter != nil {
		unitHook, finishedMetrics := sources.NewUnitHook(ctx)
		opts = append(opts, sources.WithReportHook(unitHook))
		e.wgDetectorWorkers.Add(1)
		go func() {
			defer e.wgDetectorWorkers.Done()
			defer func() {
				e.jobReportWriter.Close()
				// Add a bit of extra information if it's a *os.File.
				if namer, ok := e.jobReportWriter.(interface{ Name() string }); ok {
					ctx.Logger().Info("report written", "path", namer.Name())
				} else {
					ctx.Logger().Info("report written")
				}
			}()
			for metrics := range finishedMetrics {
				metrics.Errors = common.ExportErrors(metrics.Errors...)
				details, err := json.Marshal(map[string]any{
					"version": 1,
					"data":    metrics,
				})
				if err != nil {
					ctx.Logger().Error(err, "error marshalling job details")
					continue
				}
				if _, err := e.jobReportWriter.Write(append(details, '\n')); err != nil {
					ctx.Logger().Error(err, "error writing to file")
				}
			}
		}()
	}
	e.sourceManager = sources.NewManager(opts...)
}

// setDefaults ensures that if specific engine properties aren't provided,
// they're set to reasonable default values. It makes the engine robust to
// incomplete configuration.
func (e *Engine) setDefaults(ctx context.Context) {
	if e.concurrency == 0 {
		numCPU := runtime.NumCPU()
		ctx.Logger().Info("No concurrency specified, defaulting to max", "cpu", numCPU)
		e.concurrency = numCPU
	}
	ctx.Logger().V(3).Info("engine started", "workers", e.concurrency)

	// Default decoders handle common encoding formats.
	if len(e.decoders) == 0 {
		e.decoders = decoders.DefaultDecoders()
	}

	if len(e.detectors) == 0 {
		e.detectors = DefaultDetectors()
	}
	ctx.Logger().V(4).Info("default engine options set")
}

// Sanity check detectors for duplicate configuration. Only log in case
// a detector has been configured in a way that isn't represented by
// the DetectorID (type and version).
func (e *Engine) sanityChecks(ctx context.Context) {
	seenDetectors := make(map[config.DetectorID]struct{}, len(e.detectors))
	for _, det := range e.detectors {
		id := config.GetDetectorID(det)
		if _, ok := seenDetectors[id]; ok && id.ID != detectorspb.DetectorType_CustomRegex {
			ctx.Logger().Info("possible duplicate detector configured", "detector", id)
		}
		seenDetectors[id] = struct{}{}
	}
}

// startWorkers initiates all necessary workers. Workers handle processing of
// chunks concurrently. Separating the initialization of different types of
// workers helps in scalability and makes it easier to diagnose issues.
func (e *Engine) startWorkers(ctx context.Context) {
	// Scanner workers process input data and extract chunks for detectors.
	ctx.Logger().V(2).Info("starting scanner workers", "count", e.concurrency)
	for worker := uint64(0); worker < uint64(e.concurrency); worker++ {
		e.workersWg.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "secret_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.workersWg.Done()
			e.detectorWorker(ctx)
		}()
	}

	// Detector workers apply keyword matching, regexes and API calls to detect secrets in chunks.
	const detectorWorkerMultiplier = 50
	ctx.Logger().V(2).Info("starting detector workers", "count", e.concurrency*detectorWorkerMultiplier)
	for worker := uint64(0); worker < uint64(e.concurrency*detectorWorkerMultiplier); worker++ {
		e.wgDetectorWorkers.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "detector_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.wgDetectorWorkers.Done()
			e.detectChunks(ctx)
		}()
	}

	// verificationOverlap workers handle verification of chunks that have been detected by multiple detectors.
	// They ensure that verification is disabled for any secrets that have been detected by multiple detectors.
	const verificationOverlapWorkerMultiplier = detectorWorkerMultiplier
	ctx.Logger().V(2).Info("starting verificationOverlap workers", "count", e.concurrency)
	for worker := uint64(0); worker < uint64(e.concurrency*verificationOverlapWorkerMultiplier); worker++ {
		e.verificationOverlapWg.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "verification_overlap_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.verificationOverlapWg.Done()
			e.verificationOverlapWorker(ctx)
		}()
	}

	// Notifier workers communicate detected issues to the user or any downstream systems.
	// We want 1/4th of the notifier workers as the number of scanner workers.
	const notifierWorkerRatio = 4
	maxNotifierWorkers := 1
	if numWorkers := e.concurrency / notifierWorkerRatio; numWorkers > 0 {
		maxNotifierWorkers = int(numWorkers)
	}
	ctx.Logger().V(2).Info("starting notifier workers", "count", maxNotifierWorkers)
	for worker := 0; worker < maxNotifierWorkers; worker++ {
		e.WgNotifier.Add(1)
		go func() {
			ctx := context.WithValue(ctx, "notifier_worker_id", common.RandomID(5))
			defer common.Recover(ctx)
			defer e.WgNotifier.Done()
			e.notifyResults(ctx)
		}()
	}
}

// Finish waits for running sources to complete and workers to finish scanning
// chunks before closing their respective channels. Once Finish is called, no
// more sources may be scanned by the engine.
func (e *Engine) Finish(ctx context.Context) error {
	defer common.RecoverWithExit(ctx)
	// Wait for the sources to finish putting chunks onto the chunks channel.
	err := e.sourceManager.Wait()

	e.workersWg.Wait() // Wait for the workers to finish scanning chunks.

	close(e.verificationOverlapChunksChan)
	e.verificationOverlapWg.Wait()

	close(e.detectableChunksChan)
	e.wgDetectorWorkers.Wait() // Wait for the detector workers to finish detecting chunks.

	close(e.results)    // Detector workers are done, close the results channel and call it a day.
	e.WgNotifier.Wait() // Wait for the notifier workers to finish notifying results.

	e.metrics.ScanDuration = time.Since(e.metrics.scanStartTime)

	return err
}

func (e *Engine) ChunksChan() <-chan *sources.Chunk {
	return e.sourceManager.Chunks()
}

func (e *Engine) ResultsChan() chan detectors.ResultWithMetadata {
	return e.results
}

// ScanChunk injects a chunk into the output stream of chunks to be scanned.
// This method should rarely be used. TODO(THOG-1577): Remove when dependencies
// no longer rely on this functionality.
func (e *Engine) ScanChunk(chunk *sources.Chunk) {
	e.sourceManager.ScanChunk(chunk)
}

// detectableChunk is a decoded chunk that is ready to be scanned by its detector.
type detectableChunk struct {
	detector detectors.Detector
	chunk    sources.Chunk
	decoder  detectorspb.DecoderType
	wgDoneFn func()
}

// verificationOverlapChunk is a decoded chunk that has multiple detectors that match it.
// It will be initially processed with verification disabled, and then reprocessed with verification
// enabled if the same secret was not found by multiple detectors.
type verificationOverlapChunk struct {
	chunk                       sources.Chunk
	decoder                     detectorspb.DecoderType
	detectors                   []ahocorasick.DetectorInfo
	verificationOverlapWgDoneFn func()
}

func (e *Engine) detectorWorker(ctx context.Context) {
	var wgDetect sync.WaitGroup
	var wgVerificationOverlap sync.WaitGroup

	// Reuse the same map to avoid allocations.
	const avgDetectorsPerChunk = 8
	chunkSpecificDetectors := make(map[ahocorasick.DetectorKey]detectors.Detector, avgDetectorsPerChunk)
	for originalChunk := range e.ChunksChan() {
		for chunk := range sources.Chunker(originalChunk) {
			atomic.AddUint64(&e.metrics.BytesScanned, uint64(len(chunk.Data)))
			for _, decoder := range e.decoders {
				decoded := decoder.FromChunk(chunk)
				if decoded == nil {
					ctx.Logger().V(4).Info("no decoder found for chunk", "chunk", chunk)
					continue
				}

				matchingDetectors := e.ahoCorasickCore.PopulateMatchingDetectors(string(decoded.Chunk.Data), chunkSpecificDetectors)
				if len(chunkSpecificDetectors) > 1 && !e.verificationOverlap {
					wgVerificationOverlap.Add(1)
					e.verificationOverlapChunksChan <- verificationOverlapChunk{
						chunk:                       *decoded.Chunk,
						detectors:                   matchingDetectors,
						decoder:                     decoded.DecoderType,
						verificationOverlapWgDoneFn: wgVerificationOverlap.Done,
					}
					// Empty the map.
					for k := range chunkSpecificDetectors {
						delete(chunkSpecificDetectors, k)
					}
					continue
				}

				for k, detector := range chunkSpecificDetectors {
					decoded.Chunk.Verify = e.verify
					wgDetect.Add(1)
					e.detectableChunksChan <- detectableChunk{
						chunk:    *decoded.Chunk,
						detector: detector,
						decoder:  decoded.DecoderType,
						wgDoneFn: wgDetect.Done,
					}
					delete(chunkSpecificDetectors, k)
				}
			}
		}
		atomic.AddUint64(&e.metrics.ChunksScanned, 1)
	}

	wgVerificationOverlap.Wait()
	wgDetect.Wait()
	ctx.Logger().V(4).Info("finished scanning chunks")
}

// chunkSecretKey ties secrets to the specific detector that found them. This allows identifying identical
// credentials extracted by multiple different detectors processing the same chunk. Or duplicates found
// by the same detector in the chunk. Exact matches on lookup indicate a duplicate secret for a detector
// in that chunk - which is expected and not malicious. Those intra-detector dupes are still verified.
type chunkSecretKey struct {
	secret      string
	detectorKey ahocorasick.DetectorKey
}

func likelyDuplicate(ctx context.Context, val chunkSecretKey, dupes map[chunkSecretKey]struct{}) bool {
	const similarityThreshold = 0.9

	valStr := val.secret
	for dupeKey := range dupes {
		dupe := dupeKey.secret
		// Avoid comparing strings of vastly different lengths.
		if len(dupe)*10 < len(valStr)*9 || len(dupe)*10 > len(valStr)*11 {
			continue
		}

		// If the detector type is the same, we don't need to compare the strings.
		// These are not duplicates, and should be verified.
		if val.detectorKey.Type() == dupeKey.detectorKey.Type() {
			continue
		}

		if valStr == dupe {
			ctx.Logger().V(2).Info(
				"found exact duplicate",
			)
			return true
		}

		similarity := strutil.Similarity(valStr, dupe, metrics.NewLevenshtein())

		// close enough
		if similarity > similarityThreshold {
			ctx.Logger().V(2).Info(
				"found similar duplicate",
			)
			return true
		}
	}
	return false
}

func (e *Engine) verificationOverlapWorker(ctx context.Context) {
	var wgDetect sync.WaitGroup

	// Reuse the same map and slice to avoid allocations.
	const avgSecretsPerDetector = 8
	detectorKeysWithResults := make(map[ahocorasick.DetectorKey]struct{}, avgSecretsPerDetector)
	chunkSecrets := make(map[chunkSecretKey]struct{}, avgSecretsPerDetector)

	for chunk := range e.verificationOverlapChunksChan {
		for _, detector := range chunk.detectors {
			// DO NOT VERIFY at this stage of the pipeline.
			results, err := detector.FromData(ctx, false, chunk.chunk.Data)
			if err != nil {
				ctx.Logger().Error(err, "error verifying chunk")
			}

			if len(results) == 0 {
				continue
			}
			if _, ok := detectorKeysWithResults[detector.Key]; !ok {
				detectorKeysWithResults[detector.Key] = struct{}{}
			}

			for _, res := range results {
				var val []byte
				if res.RawV2 != nil {
					val = res.RawV2
				} else {
					val = res.Raw
				}

				// Use levenstein distance to determine if the secret is likely the same.
				// Ex:
				// - postman api key: PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
				// - malicious detector "api key": qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r
				key := chunkSecretKey{secret: string(val), detectorKey: detector.Key}
				if _, ok := chunkSecrets[key]; ok {
					continue
				}

				if likelyDuplicate(ctx, key, chunkSecrets) {
					// This indicates that the same secret was found by multiple detectors.
					// We should NOT VERIFY this chunk's data.
					if e.verificationOverlapTracker != nil {
						e.verificationOverlapTracker.increment()
					}
					res.SetVerificationError(overlapError)
					e.processResult(ctx, detectableChunk{
						chunk:    chunk.chunk,
						detector: detector,
						decoder:  chunk.decoder,
						wgDoneFn: wgDetect.Done,
					}, res)

					// Remove the detector key from the list of detector keys with results.
					// This is to ensure that the chunk is not reprocessed with verification enabled
					// for this detector.
					delete(detectorKeysWithResults, detector.Key)
				}
				chunkSecrets[key] = struct{}{}
			}
		}

		for key := range detectorKeysWithResults {
			detector := e.ahoCorasickCore.GetDetectorByKey(key)
			if detector == nil {
				ctx.Logger().Info("detector not found", "key", key)
				continue
			}

			wgDetect.Add(1)
			chunk.chunk.Verify = e.verify
			e.detectableChunksChan <- detectableChunk{
				chunk:    chunk.chunk,
				detector: detector,
				decoder:  chunk.decoder,
				wgDoneFn: wgDetect.Done,
			}
		}

		// Empty the dupes and detectors slice
		for k := range chunkSecrets {
			delete(chunkSecrets, k)
		}
		for k := range detectorKeysWithResults {
			delete(detectorKeysWithResults, k)
		}

		chunk.verificationOverlapWgDoneFn()
	}

	wgDetect.Wait()
	ctx.Logger().V(4).Info("finished verificationOverlap chunks")
}

func (e *Engine) detectChunks(ctx context.Context) {
	for data := range e.detectableChunksChan {
		e.detectChunk(ctx, data)
	}
}

func (e *Engine) detectChunk(ctx context.Context, data detectableChunk) {
	var start time.Time
	if e.printAvgDetectorTime {
		start = time.Now()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer common.Recover(ctx)
	defer cancel()

	results, err := data.detector.FromData(ctx, data.chunk.Verify, data.chunk.Data)
	if err != nil {
		ctx.Logger().Error(err, "error scanning chunk")
	}

	if e.printAvgDetectorTime && len(results) > 0 {
		elapsed := time.Since(start)
		detectorName := results[0].DetectorType.String()
		avgTimeI, ok := e.metrics.detectorAvgTime.Load(detectorName)
		var avgTime []time.Duration
		if ok {
			avgTime, ok = avgTimeI.([]time.Duration)
			if !ok {
				return
			}
		}
		avgTime = append(avgTime, elapsed)
		e.metrics.detectorAvgTime.Store(detectorName, avgTime)
	}

	if e.filterUnverified {
		results = detectors.CleanResults(results)
	}

	if e.filterEntropy != nil {
		results = detectors.FilterResultsWithEntropy(results, *e.filterEntropy)
	}

	for _, res := range results {
		e.processResult(ctx, data, res)
	}
	data.wgDoneFn()
}

func (e *Engine) processResult(ctx context.Context, data detectableChunk, res detectors.Result) {
	ignoreLinePresent := false
	if SupportsLineNumbers(data.chunk.SourceType) {
		copyChunk := data.chunk
		copyMetaDataClone := proto.Clone(data.chunk.SourceMetadata)
		if copyMetaData, ok := copyMetaDataClone.(*source_metadatapb.MetaData); ok {
			copyChunk.SourceMetadata = copyMetaData
		}
		fragStart, mdLine, link := FragmentFirstLineAndLink(&copyChunk)
		ignoreLinePresent = SetResultLineNumber(&copyChunk, &res, fragStart, mdLine)
		if err := UpdateLink(ctx, copyChunk.SourceMetadata, link, *mdLine); err != nil {
			ctx.Logger().Error(err, "error setting link")
			return
		}
		data.chunk = copyChunk
	}
	if ignoreLinePresent {
		return
	}

	secret := detectors.CopyMetadata(&data.chunk, res)
	secret.DecoderType = data.decoder
	e.results <- secret
}

func (e *Engine) notifyResults(ctx context.Context) {
	for r := range e.ResultsChan() {
		// Filter unwanted results, based on `--results`.
		if !r.Verified {
			if r.VerificationError() != nil {
				if !e.notifyUnknownResults {
					// Skip results with verification errors.
					continue
				}
			} else if !e.notifyUnverifiedResults {
				// Skip unverified results.
				continue
			}
		} else if !e.notifyVerifiedResults {
			// Skip verified results.
			// TODO: Is this a legitimate use case?
			continue
		}
		atomic.AddUint32(&e.numFoundResults, 1)

		// Dedupe results by comparing the detector type, raw result, and source metadata.
		// We want to avoid duplicate results with different decoder types, but we also
		// want to include duplicate results with the same decoder type.
		// Duplicate results with the same decoder type SHOULD have their own entry in the
		// results list, this would happen if the same secret is found multiple times.
		// Note: If the source type is postman, we dedupe the results regardless of decoder type.
		key := fmt.Sprintf("%s%s%s%+v", r.DetectorType.String(), r.Raw, r.RawV2, r.SourceMetadata)
		if val, ok := e.dedupeCache.Get(key); ok && (val != r.DecoderType ||
			r.SourceType == sourcespb.SourceType_SOURCE_TYPE_POSTMAN) {
			continue
		}
		e.dedupeCache.Add(key, r.DecoderType)

		if r.Verified {
			atomic.AddUint64(&e.metrics.VerifiedSecretsFound, 1)
		} else {
			atomic.AddUint64(&e.metrics.UnverifiedSecretsFound, 1)
		}

		if err := e.printer.Print(ctx, &r); err != nil {
			ctx.Logger().Error(err, "error printing result")
		}
	}
}

// SupportsLineNumbers determines if a line number can be found for a source type.
func SupportsLineNumbers(sourceType sourcespb.SourceType) bool {
	switch sourceType {
	case sourcespb.SourceType_SOURCE_TYPE_GIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		sourcespb.SourceType_SOURCE_TYPE_GITLAB,
		sourcespb.SourceType_SOURCE_TYPE_BITBUCKET,
		sourcespb.SourceType_SOURCE_TYPE_GERRIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB_UNAUTHENTICATED_ORG,
		sourcespb.SourceType_SOURCE_TYPE_PUBLIC_GIT,
		sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM,
		sourcespb.SourceType_SOURCE_TYPE_AZURE_REPOS:
		return true
	default:
		return false
	}
}

// FragmentLineOffset sets the line number for a provided source chunk with a given detector result.
func FragmentLineOffset(chunk *sources.Chunk, result *detectors.Result) (int64, bool) {
	before, after, found := bytes.Cut(chunk.Data, result.Raw)
	if !found {
		return 0, false
	}
	lineNumber := int64(bytes.Count(before, []byte("\n")))
	// If the line contains the ignore tag, we should ignore the result.
	endLine := bytes.Index(after, []byte("\n"))
	if endLine == -1 {
		endLine = len(after)
	}
	if bytes.Contains(after[:endLine], []byte(ignoreTag)) {
		return lineNumber, true
	}
	return lineNumber, false
}

// FragmentFirstLineAndLink extracts the first line number and the link from the chunk metadata.
// It returns:
//   - The first line number of the fragment.
//   - A pointer to the line number, facilitating direct updates.
//   - The link associated with the fragment. This link may be updated in the chunk metadata
//     if there's a change in the line number.
func FragmentFirstLineAndLink(chunk *sources.Chunk) (int64, *int64, string) {
	if chunk.SourceMetadata == nil {
		return 0, nil, ""
	}

	var (
		fragmentStart *int64
		link          string
	)
	switch metadata := chunk.SourceMetadata.GetData().(type) {
	case *source_metadatapb.MetaData_Git:
		fragmentStart = &metadata.Git.Line
	case *source_metadatapb.MetaData_Github:
		fragmentStart = &metadata.Github.Line
		link = metadata.Github.Link
	case *source_metadatapb.MetaData_Gitlab:
		fragmentStart = &metadata.Gitlab.Line
		link = metadata.Gitlab.Link
	case *source_metadatapb.MetaData_Bitbucket:
		fragmentStart = &metadata.Bitbucket.Line
		link = metadata.Bitbucket.Link
	case *source_metadatapb.MetaData_Gerrit:
		fragmentStart = &metadata.Gerrit.Line
	case *source_metadatapb.MetaData_Filesystem:
		fragmentStart = &metadata.Filesystem.Line
		link = metadata.Filesystem.Link
	case *source_metadatapb.MetaData_AzureRepos:
		fragmentStart = &metadata.AzureRepos.Line
		link = metadata.AzureRepos.Link
	default:
		return 0, nil, ""
	}
	return *fragmentStart, fragmentStart, link
}

// SetResultLineNumber sets the line number in the provided result.
func SetResultLineNumber(chunk *sources.Chunk, result *detectors.Result, fragStart int64, mdLine *int64) bool {
	offset, skip := FragmentLineOffset(chunk, result)
	*mdLine = fragStart + offset
	return skip
}

// UpdateLink updates the link of the provided source metadata.
func UpdateLink(ctx context.Context, metadata *source_metadatapb.MetaData, link string, line int64) error {
	if metadata == nil {
		return fmt.Errorf("metadata is nil when setting the link")
	}

	if link == "" {
		ctx.Logger().V(4).Info("link is empty, skipping update")
		return nil
	}

	newLink := giturl.UpdateLinkLineNumber(ctx, link, line)

	switch meta := metadata.GetData().(type) {
	case *source_metadatapb.MetaData_Github:
		meta.Github.Link = newLink
	case *source_metadatapb.MetaData_Gitlab:
		meta.Gitlab.Link = newLink
	case *source_metadatapb.MetaData_Bitbucket:
		meta.Bitbucket.Link = newLink
	case *source_metadatapb.MetaData_Filesystem:
		meta.Filesystem.Link = newLink
	case *source_metadatapb.MetaData_AzureRepos:
		meta.AzureRepos.Link = newLink
	default:
		return fmt.Errorf("unsupported metadata type")
	}
	return nil
}
