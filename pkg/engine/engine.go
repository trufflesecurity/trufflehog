package engine

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"google.golang.org/protobuf/proto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/output"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

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

// detectorKey is used to identify a detector in the keywordsToDetectors map.
// Multiple detectors can have the same detector type but different versions.
// This allows us to identify a detector by its type and version.
type detectorKey struct {
	detectorType detectorspb.DetectorType
	version      int
}

// detectorInfo is used to store a detector and whether it should be verified.
type detectorInfo struct {
	detectors.Detector
	shouldVerify bool
}

type Engine struct {
	// CLI flags.
	concurrency uint8
	decoders    []decoders.Decoder
	detectors   map[bool][]detectors.Detector
	// filterUnverified is used to reduce the number of unverified results.
	// If there are multiple unverified results for the same chunk for the same detector,
	// only the first one will be kept.
	filterUnverified     bool
	onlyVerified         bool
	printAvgDetectorTime bool

	// ahoCorasickHandler manages the Aho-Corasick trie and related keyword lookups
	ahoCorasickCore *ahoCorasickCore

	// Engine synchronization primitives.
	sourceManager        *sources.SourceManager
	results              chan detectors.ResultWithMetadata
	detectableChunksChan chan detectableChunk
	workersWg            sync.WaitGroup
	wgDetectorWorkers    sync.WaitGroup
	WgNotifier           sync.WaitGroup

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
	dedupeCache *lru.Cache
}

// Option is used to configure the engine during initialization using functional options.
type Option func(*Engine)

func WithConcurrency(concurrency uint8) Option {
	return func(e *Engine) {
		e.concurrency = concurrency
	}
}

const ignoreTag = "trufflehog:ignore"

func WithDetectors(verify bool, d ...detectors.Detector) Option {
	return func(e *Engine) {
		if e.detectors == nil {
			e.detectors = make(map[bool][]detectors.Detector)
		}
		if e.detectors[verify] == nil {
			e.detectors[true] = []detectors.Detector{}
			e.detectors[false] = []detectors.Detector{}
		}
		e.detectors[verify] = append(e.detectors[verify], d...)
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

// WithOnlyVerified sets the onlyVerified flag on the engine. If set to true,
// the engine will only print verified results.
func WithOnlyVerified(onlyVerified bool) Option {
	return func(e *Engine) {
		e.onlyVerified = onlyVerified
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
		e.detectors[true] = filterDetectors(filterFunc, e.detectors[true])
		e.detectors[false] = filterDetectors(filterFunc, e.detectors[false])
	}
}

// WithPrinter sets the Printer on the engine.
func WithPrinter(printer Printer) Option {
	return func(e *Engine) {
		e.printer = printer
	}
}

func filterDetectors(filterFunc func(detectors.Detector) bool, input []detectors.Detector) []detectors.Detector {
	var output []detectors.Detector
	for _, detector := range input {
		if filterFunc(detector) {
			output = append(output, detector)
		}
	}
	return output
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
	e.setDefaults(ctx)
	e.ahoCorasickCore.setup(ctx)
	e.sanityChecks(ctx)
	e.startWorkers(ctx)

	return e, nil
}

const defaultChannelBuffer = 1

// initialize prepares the engine's internal structures. The LRU cache optimizes
// deduplication efforts, allowing the engine to quickly check if a chunk has
// been processed before, thereby saving computational overhead.
func (e *Engine) initialize(ctx context.Context, options ...Option) error {
	// TODO (ahrav): Determine the optimal cache size.
	const cacheSize = 512 // number of entries in the LRU cache

	cache, err := lru.New(cacheSize)
	if err != nil {
		return fmt.Errorf("failed to initialize LRU cache: %w", err)
	}

	// Channels are used for communication between different parts of the engine,
	// ensuring that data flows smoothly without race conditions.
	e.detectableChunksChan = make(chan detectableChunk, defaultChannelBuffer)
	e.results = make(chan detectors.ResultWithMetadata, defaultChannelBuffer)
	e.dedupeCache = cache
	e.printer = new(output.PlainPrinter)
	e.metrics = runtimeMetrics{Metrics: Metrics{scanStartTime: time.Now()}}

	for _, option := range options {
		option(e)
	}
	ctx.Logger().V(4).Info("engine initialized")
	ctx.Logger().V(4).Info("setting up aho-corasick core")
	e.ahoCorasickCore = newAhoCorasickCore(e.detectors)

	return nil
}

// setDefaults ensures that if specific engine properties aren't provided,
// they're set to reasonable default values. It makes the engine robust to
// incomplete configuration.
func (e *Engine) setDefaults(ctx context.Context) {
	if e.concurrency == 0 {
		numCPU := runtime.NumCPU()
		ctx.Logger().Info("No concurrency specified, defaulting to max", "cpu", numCPU)
		e.concurrency = uint8(numCPU)
	}
	ctx.Logger().V(3).Info("engine started", "workers", e.concurrency)

	e.sourceManager = sources.NewManager(
		sources.WithConcurrentSources(int(e.concurrency)),
		sources.WithConcurrentUnits(int(e.concurrency)),
		sources.WithBufferedOutput(defaultChannelBuffer),
	)

	// Default decoders handle common encoding formats.
	if len(e.decoders) == 0 {
		e.decoders = decoders.DefaultDecoders()
	}

	if len(e.detectors) == 0 {
		e.detectors = map[bool][]detectors.Detector{}
		e.detectors[true] = DefaultDetectors()
		e.detectors[false] = []detectors.Detector{}
	}
	ctx.Logger().V(4).Info("default engine options set")
}

// Sanity check detectors for duplicate configuration. Only log in case
// a detector has been configured in a way that isn't represented by
// the DetectorID (type and version).
func (e *Engine) sanityChecks(ctx context.Context) {
	dets := append(e.detectors[true], e.detectors[false]...)
	seenDetectors := make(map[config.DetectorID]struct{}, len(dets))
	for _, det := range dets {
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

	// Detector workers apply keyword matching, regexes and API calls to
	// detect secrets in chunks.
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
// This method should rarely be used. TODO: Remove when dependencies no longer
// rely on this functionality.
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

func (e *Engine) detectorWorker(ctx context.Context) {
	var wgDetect sync.WaitGroup

	// Reuse the same map to avoid allocations.
	const avgDetectorsPerChunk = 2
	chunkSpecificDetectors := make(map[detectorspb.DetectorType]detectorInfo, avgDetectorsPerChunk)
	for originalChunk := range e.ChunksChan() {
		for chunk := range sources.Chunker(originalChunk) {
			atomic.AddUint64(&e.metrics.BytesScanned, uint64(len(chunk.Data)))
			for _, decoder := range e.decoders {
				decoded := decoder.FromChunk(chunk)
				if decoded == nil {
					ctx.Logger().V(4).Info("no decoder found for chunk", "chunk", chunk)
					continue
				}

				for _, match := range e.ahoCorasickCore.matchString(strings.ToLower(string(decoded.Chunk.Data))) {
					if !e.ahoCorasickCore.populateDetectorsByMatch(match, chunkSpecificDetectors) {
						continue
					}
				}

				for k, detector := range chunkSpecificDetectors {
					decoded.Chunk.Verify = detector.shouldVerify
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
	wgDetect.Wait()
	ctx.Logger().V(4).Info("finished scanning chunks")
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

	for _, res := range results {
		e.processResult(data, res)
	}
	data.wgDoneFn()
}

func (e *Engine) processResult(data detectableChunk, res detectors.Result) {
	ignoreLinePresent := false
	if SupportsLineNumbers(data.chunk.SourceType) {
		copyChunk := data.chunk
		copyMetaDataClone := proto.Clone(data.chunk.SourceMetadata)
		if copyMetaData, ok := copyMetaDataClone.(*source_metadatapb.MetaData); ok {
			copyChunk.SourceMetadata = copyMetaData
		}
		fragStart, mdLine := FragmentFirstLine(&copyChunk)
		ignoreLinePresent = SetResultLineNumber(&copyChunk, &res, fragStart, mdLine)
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
		if e.onlyVerified && !r.Verified {
			continue
		}
		atomic.AddUint32(&e.numFoundResults, 1)

		key := fmt.Sprintf("%s%s%s%+v", r.DetectorType.String(), r.Raw, r.RawV2, r.SourceMetadata)
		if _, ok := e.dedupeCache.Get(key); ok {
			continue
		}
		e.dedupeCache.Add(key, struct{}{})

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
		sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM:
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

// FragmentFirstLine returns the first line number of a fragment along with a pointer to the value to update in the
// chunk metadata.
func FragmentFirstLine(chunk *sources.Chunk) (int64, *int64) {
	var fragmentStart *int64
	switch metadata := chunk.SourceMetadata.GetData().(type) {
	case *source_metadatapb.MetaData_Git:
		fragmentStart = &metadata.Git.Line
	case *source_metadatapb.MetaData_Github:
		fragmentStart = &metadata.Github.Line
	case *source_metadatapb.MetaData_Gitlab:
		fragmentStart = &metadata.Gitlab.Line
	case *source_metadatapb.MetaData_Bitbucket:
		fragmentStart = &metadata.Bitbucket.Line
	case *source_metadatapb.MetaData_Gerrit:
		fragmentStart = &metadata.Gerrit.Line
	case *source_metadatapb.MetaData_Filesystem:
		fragmentStart = &metadata.Filesystem.Line
	default:
		return 0, nil
	}
	return *fragmentStart, fragmentStart
}

// SetResultLineNumber sets the line number in the provided result.
func SetResultLineNumber(chunk *sources.Chunk, result *detectors.Result, fragStart int64, mdLine *int64) bool {
	offset, skip := FragmentLineOffset(chunk, result)
	*mdLine = fragStart + offset
	return skip
}
