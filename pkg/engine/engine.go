package engine

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Engine struct {
	concurrency     int
	chunks          chan *sources.Chunk
	results         chan detectors.ResultWithMetadata
	decoders        []decoders.Decoder
	detectors       map[bool][]detectors.Detector
	chunksScanned   uint64
	bytesScanned    uint64
	detectorAvgTime sync.Map
	sourcesWg       *errgroup.Group
	workersWg       sync.WaitGroup
	// filterUnverified is used to reduce the number of unverified results.
	// If there are multiple unverified results for the same chunk for the same detector,
	// only the first one will be kept.
	filterUnverified bool

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.Trie
}

type EngineOption func(*Engine)

func WithConcurrency(concurrency int) EngineOption {
	return func(e *Engine) {
		e.concurrency = concurrency
	}
}

const ignoreTag = "trufflehog:ignore"

func WithDetectors(verify bool, d ...detectors.Detector) EngineOption {
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

func WithDecoders(decoders ...decoders.Decoder) EngineOption {
	return func(e *Engine) {
		e.decoders = decoders
	}
}

// WithFilterUnverified sets the filterUnverified flag on the engine. If set to
// true, the engine will only return the first unverified result for a chunk for a detector.
func WithFilterUnverified(filter bool) EngineOption {
	return func(e *Engine) {
		e.filterUnverified = filter
	}
}

// WithFilterDetectors applies a filter to the configured list of detectors. If
// the filterFunc returns true, the detector will be included for scanning.
// This option applies to the existing list of detectors configured, so the
// order this option appears matters. All filtering happens before scanning.
func WithFilterDetectors(filterFunc func(detectors.Detector) bool) EngineOption {
	return func(e *Engine) {
		// If no detectors are configured, do nothing.
		if e.detectors == nil {
			return
		}
		e.detectors[true] = filterDetectors(filterFunc, e.detectors[true])
		e.detectors[false] = filterDetectors(filterFunc, e.detectors[false])
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

func Start(ctx context.Context, options ...EngineOption) *Engine {
	e := &Engine{
		chunks:          make(chan *sources.Chunk),
		results:         make(chan detectors.ResultWithMetadata),
		detectorAvgTime: sync.Map{},
		sourcesWg:       &errgroup.Group{},
	}

	for _, option := range options {
		option(e)
	}

	// Set defaults.
	if e.concurrency == 0 {
		numCPU := runtime.NumCPU()
		ctx.Logger().Info("No concurrency specified, defaulting to max", "cpu", numCPU)
		e.concurrency = numCPU
	}
	ctx.Logger().V(2).Info("engine started", "workers", e.concurrency)

	// Limit number of concurrent goroutines dedicated to chunking a source.
	e.sourcesWg.SetLimit(e.concurrency)

	if len(e.decoders) == 0 {
		e.decoders = decoders.DefaultDecoders()
	}

	if len(e.detectors) == 0 {
		e.detectors = map[bool][]detectors.Detector{}
		e.detectors[true] = DefaultDetectors()
		e.detectors[false] = []detectors.Detector{}
	}

	// build ahocorasick prefilter for efficient string matching
	// on keywords
	keywords := []string{}
	for _, d := range e.detectors[false] {
		keywords = append(keywords, d.Keywords()...)
	}
	for _, d := range e.detectors[true] {
		keywords = append(keywords, d.Keywords()...)
	}
	e.prefilter = *ahocorasick.NewTrieBuilder().AddStrings(keywords).Build()

	ctx.Logger().Info("loaded decoders", "count", len(e.decoders))
	ctx.Logger().Info("loaded detectors",
		"total", len(e.detectors[true])+len(e.detectors[false]),
		"verification_enabled", len(e.detectors[true]),
		"verification_disabled", len(e.detectors[false]),
	)

	// Sanity check detectors for duplicate configuration. Only log in case
	// a detector has been configured in a way that isn't represented by
	// the DetectorID (type and version).
	{
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

	// Start the workers.
	for i := 0; i < e.concurrency; i++ {
		e.workersWg.Add(1)
		go func() {
			defer common.Recover(ctx)
			defer e.workersWg.Done()
			e.detectorWorker(ctx)
		}()
	}

	return e
}

// Finish waits for running sources to complete and workers to finish scanning
// chunks before closing their respective channels. Once Finish is called, no
// more sources may be scanned by the engine.
func (e *Engine) Finish(ctx context.Context, logFunc func(error, string, ...any)) {
	defer common.RecoverWithExit(ctx)
	// wait for the sources to finish putting chunks onto the chunks channel
	sourceErr := e.sourcesWg.Wait()
	if sourceErr != nil {
		logFunc(sourceErr, "error occurred while collecting chunks")
	}

	close(e.chunks)
	// wait for the workers to finish processing all of the chunks and putting
	// results onto the results channel
	e.workersWg.Wait()

	// TODO: re-evaluate whether this is needed and investigate why if so
	//
	// not entirely sure why results don't get processed without this pause
	// since we've put all results on the channel at this point.
	time.Sleep(time.Second)
	close(e.results)
}

func (e *Engine) ChunksChan() chan *sources.Chunk {
	return e.chunks
}

func (e *Engine) ResultsChan() chan detectors.ResultWithMetadata {
	return e.results
}

func (e *Engine) ChunksScanned() uint64 {
	return e.chunksScanned
}

func (e *Engine) BytesScanned() uint64 {
	return e.bytesScanned
}

func (e *Engine) dedupeAndSend(chunkResults []detectors.ResultWithMetadata) {
	dedupeMap := make(map[string]struct{})
	for _, result := range chunkResults {
		// dedupe by comparing the detector type, raw result, and source metadata
		// NOTE: in order for the PLAIN decoder to maintain precedence, make sure UTF8 is the first decoder in the
		// default decoders list
		key := fmt.Sprintf("%s%s%s%+v", result.DetectorType.String(), result.Raw, result.RawV2, result.SourceMetadata)
		if _, ok := dedupeMap[key]; ok {
			continue
		}
		dedupeMap[key] = struct{}{}
		e.results <- result
	}

}

func (e *Engine) DetectorAvgTime() map[string][]time.Duration {
	logger := context.Background().Logger()
	avgTime := map[string][]time.Duration{}
	e.detectorAvgTime.Range(func(k, v interface{}) bool {
		key, ok := k.(string)
		if !ok {
			logger.Info("expected DetectorAvgTime key to be a string")
			return true
		}

		value, ok := v.([]time.Duration)
		if !ok {
			logger.Info("expected DetectorAvgTime value to be []time.Duration")
			return true
		}
		avgTime[key] = value
		return true
	})
	return avgTime
}

func (e *Engine) detectorWorker(ctx context.Context) {
	for originalChunk := range e.chunks {
		for chunk := range sources.Chunker(originalChunk) {
			var chunkResults []detectors.ResultWithMetadata
			matchedKeywords := make(map[string]struct{})
			atomic.AddUint64(&e.bytesScanned, uint64(len(chunk.Data)))
			for _, decoder := range e.decoders {
				var decoderType detectorspb.DecoderType
				switch decoder.(type) {
				case *decoders.UTF8:
					decoderType = detectorspb.DecoderType_PLAIN
				case *decoders.Base64:
					decoderType = detectorspb.DecoderType_BASE64
				case *decoders.UTF16:
					decoderType = detectorspb.DecoderType_UTF16
				default:
					ctx.Logger().Info("unknown decoder type", "type", reflect.TypeOf(decoder).String())
					decoderType = detectorspb.DecoderType_UNKNOWN
				}

				decoded := decoder.FromChunk(chunk)

				if decoded == nil {
					continue
				}

				// build a map of all keywords that were matched in the chunk
				for _, m := range e.prefilter.MatchString(string(decoded.Data)) {
					matchedKeywords[strings.ToLower(m.MatchString())] = struct{}{}
				}

				for verify, detectorsSet := range e.detectors {
					for _, detector := range detectorsSet {
						chunkContainsKeyword := false
						for _, kw := range detector.Keywords() {
							if _, ok := matchedKeywords[strings.ToLower(kw)]; ok {
								chunkContainsKeyword = true
								break
							}
						}

						if !chunkContainsKeyword {
							continue
						}

						start := time.Now()

						results, err := func() ([]detectors.Result, error) {
							ctx, cancel := context.WithTimeout(ctx, time.Second*10)
							defer cancel()
							defer common.Recover(ctx)
							return detector.FromData(ctx, verify, decoded.Data)
						}()
						if err != nil {
							ctx.Logger().Error(err, "could not scan chunk",
								"source_type", decoded.SourceType.String(),
								"metadata", decoded.SourceMetadata,
							)
							continue
						}

						if e.filterUnverified {
							results = detectors.CleanResults(results)
						}
						for _, result := range results {
							resultChunk := chunk
							ignoreLinePresent := false
							if SupportsLineNumbers(chunk.SourceType) {
								copyChunk := *chunk
								copyMetaDataClone := proto.Clone(chunk.SourceMetadata)
								if copyMetaData, ok := copyMetaDataClone.(*source_metadatapb.MetaData); ok {
									copyChunk.SourceMetadata = copyMetaData
								}
								fragStart, mdLine := FragmentFirstLine(&copyChunk)
								ignoreLinePresent = SetResultLineNumber(&copyChunk, &result, fragStart, mdLine)
								resultChunk = &copyChunk
							}
							if ignoreLinePresent {
								continue
							}
							result.DecoderType = decoderType
							chunkResults = append(chunkResults, detectors.CopyMetadata(resultChunk, result))

						}
						if len(results) > 0 {
							elapsed := time.Since(start)
							detectorName := results[0].DetectorType.String()
							avgTimeI, ok := e.detectorAvgTime.Load(detectorName)
							var avgTime []time.Duration
							if ok {
								avgTime, ok = avgTimeI.([]time.Duration)
								if !ok {
									continue
								}
							}
							avgTime = append(avgTime, elapsed)
							e.detectorAvgTime.Store(detectorName, avgTime)
						}
					}
				}
			}
			e.dedupeAndSend(chunkResults)
		}
		atomic.AddUint64(&e.chunksScanned, 1)
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
	lines := bytes.Split(chunk.Data, []byte("\n"))
	for i, line := range lines {
		if bytes.Contains(line, result.Raw) {
			// if the line contains the ignore tag, we should ignore the result
			if bytes.Contains(line, []byte(ignoreTag)) {
				return int64(i), true
			}
			return int64(i), false
		}
	}
	return 0, false
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
