package engine

import (
	"bytes"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
	sourcesWg       sync.WaitGroup
	workersWg       sync.WaitGroup
	// filterUnverified is used to reduce the number of unverified results.
	// If there are multiple unverified results for the same chunk for the same detector,
	// only the first one will be kept.
	filterUnverified bool
}

type EngineOption func(*Engine)

func WithConcurrency(concurrency int) EngineOption {
	return func(e *Engine) {
		e.concurrency = concurrency
	}
}

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

func Start(ctx context.Context, options ...EngineOption) *Engine {
	e := &Engine{
		chunks:          make(chan *sources.Chunk),
		results:         make(chan detectors.ResultWithMetadata),
		detectorAvgTime: sync.Map{},
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

	if len(e.decoders) == 0 {
		e.decoders = decoders.DefaultDecoders()
	}

	if len(e.detectors) == 0 {
		e.detectors = map[bool][]detectors.Detector{}
		e.detectors[true] = DefaultDetectors()
		e.detectors[false] = []detectors.Detector{}
	}

	ctx.Logger().V(2).Info("loaded decoders", "count", len(e.decoders))
	ctx.Logger().V(2).Info("loaded detectors",
		"total", len(e.detectors[true])+len(e.detectors[false]),
		"verification_enabled", len(e.detectors[true]),
		"verification_disabled", len(e.detectors[false]),
	)

	// start the workers
	for i := 0; i < e.concurrency; i++ {
		e.workersWg.Add(1)
		go func() {
			defer common.RecoverWithExit(ctx)
			defer e.workersWg.Done()
			e.detectorWorker(ctx)
		}()
	}

	return e
}

// Finish waits for running sources to complete and workers to finish scanning
// chunks before closing their respective channels. Once Finish is called, no
// more sources may be scanned by the engine.
func (e *Engine) Finish(ctx context.Context) {
	defer common.RecoverWithExit(ctx)
	// wait for the sources to finish putting chunks onto the chunks channel
	e.sourcesWg.Wait()
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
			atomic.AddUint64(&e.bytesScanned, uint64(len(chunk.Data)))
			for _, decoder := range e.decoders {
				var decoderType detectorspb.DecoderType
				switch decoder.(type) {
				case *decoders.UTF8:
					decoderType = detectorspb.DecoderType_PLAIN
				case *decoders.Base64:
					decoderType = detectorspb.DecoderType_BASE64
				default:
					ctx.Logger().Info("unknown decoder type", "type", reflect.TypeOf(decoder).String())
					decoderType = detectorspb.DecoderType_UNKNOWN
				}
				decoded := decoder.FromChunk(chunk)
				if decoded == nil {
					continue
				}
				dataLower := strings.ToLower(string(decoded.Data))
				for verify, detectorsSet := range e.detectors {
					for _, detector := range detectorsSet {
						start := time.Now()
						foundKeyword := false
						for _, kw := range detector.Keywords() {
							if strings.Contains(dataLower, strings.ToLower(kw)) {
								foundKeyword = true
								break
							}
						}
						if !foundKeyword {
							continue
						}

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
							if SupportsLineNumbers(chunk.SourceType) {
								copyChunk := *chunk
								copyMetaDataClone := proto.Clone(chunk.SourceMetadata)
								if copyMetaData, ok := copyMetaDataClone.(*source_metadatapb.MetaData); ok {
									copyChunk.SourceMetadata = copyMetaData
								}
								fragStart, mdLine := FragmentFirstLine(&copyChunk)
								SetResultLineNumber(&copyChunk, &result, fragStart, mdLine)
								resultChunk = &copyChunk
							}
							result.DecoderType = decoderType
							e.results <- detectors.CopyMetadata(resultChunk, result)

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
		}
		atomic.AddUint64(&e.chunksScanned, 1)
	}
}

// gitSources is a list of sources that utilize the Git source. It is stored this way because slice consts are not
// supported.
func gitSources() []sourcespb.SourceType {
	return []sourcespb.SourceType{
		sourcespb.SourceType_SOURCE_TYPE_GIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		sourcespb.SourceType_SOURCE_TYPE_GITLAB,
		sourcespb.SourceType_SOURCE_TYPE_BITBUCKET,
		sourcespb.SourceType_SOURCE_TYPE_GERRIT,
		sourcespb.SourceType_SOURCE_TYPE_GITHUB_UNAUTHENTICATED_ORG,
		sourcespb.SourceType_SOURCE_TYPE_PUBLIC_GIT,
	}
}

// SupportsLineNumbers determines if a line number can be found for a source type.
func SupportsLineNumbers(sourceType sourcespb.SourceType) bool {
	for _, i := range gitSources() {
		if i == sourceType {
			return true
		}
	}
	return false
}

// FragmentLineOffset sets the line number for a provided source chunk with a given detector result.
func FragmentLineOffset(chunk *sources.Chunk, result *detectors.Result) int64 {
	lines := bytes.Split(chunk.Data, []byte("\n"))
	for i, line := range lines {
		if bytes.Contains(line, result.Raw) {
			return int64(i)
		}
	}
	return 0
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
	default:
		return 0, nil
	}
	return *fragmentStart, fragmentStart
}

// SetResultLineNumber sets the line number in the provided result.
func SetResultLineNumber(chunk *sources.Chunk, result *detectors.Result, fragStart int64, mdLine *int64) {
	offset := FragmentLineOffset(chunk, result)
	*mdLine = fragStart + offset
}
