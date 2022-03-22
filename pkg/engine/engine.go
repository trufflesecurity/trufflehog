package engine

import (
	"bytes"
	"context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Engine struct {
	concurrency     int
	chunks          chan *sources.Chunk
	results         chan detectors.ResultWithMetadata
	decoders        []decoders.Decoder
	detectors       map[bool][]detectors.Detector
	chunksScanned   uint64
	detectorAvgTime sync.Map
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

func Start(ctx context.Context, options ...EngineOption) *Engine {
	e := &Engine{
		chunks:          make(chan *sources.Chunk),
		results:         make(chan detectors.ResultWithMetadata),
		detectorAvgTime: sync.Map{},
	}

	for _, option := range options {
		option(e)
	}

	// set defaults

	if e.concurrency == 0 {
		numCPU := runtime.NumCPU()
		logrus.Warn("No concurrency specified, defaulting to ", numCPU)
		e.concurrency = numCPU
	}
	logrus.Debugf("running with  up to %d workers", e.concurrency)

	var workerWg sync.WaitGroup
	for i := 0; i < e.concurrency; i++ {
		workerWg.Add(1)
		go func() {
			e.detectorWorker(ctx)
			workerWg.Done()
		}()
	}

	if len(e.decoders) == 0 {
		e.decoders = decoders.DefaultDecoders()
	}

	if len(e.detectors) == 0 {
		e.detectors = map[bool][]detectors.Detector{}
		e.detectors[true] = DefaultDetectors()
		e.detectors[false] = []detectors.Detector{}
	}

	logrus.Debugf("loaded %d decoders", len(e.decoders))
	logrus.Debugf("loaded %d detectors total, %d with verification enabled. %d with verification disabled",
		len(e.detectors[true])+len(e.detectors[false]),
		len(e.detectors[true]),
		len(e.detectors[false]))

	// start the workers
	go func() {
		// close results chan when all workers are done
		workerWg.Wait()
		// not entirely sure why results don't get processed without this pause
		// since we've put all results on the channel at this point.
		time.Sleep(time.Second)
		close(e.ResultsChan())
	}()

	return e
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

func (e *Engine) DetectorAvgTime() map[string][]time.Duration {
	avgTime := map[string][]time.Duration{}
	e.detectorAvgTime.Range(func(k, v interface{}) bool {
		key, ok := k.(string)
		if !ok {
			logrus.Warnf("expected DetectorAvgTime key to be a string")
			return true
		}

		value, ok := v.([]time.Duration)
		if !ok {
			logrus.Warnf("expected DetectorAvgTime value to be []time.Duration")
			return true
		}
		avgTime[key] = value
		return true
	})
	return avgTime
}

func (e *Engine) detectorWorker(ctx context.Context) {
	for chunk := range e.chunks {
		for _, decoder := range e.decoders {
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
					ctx, cancel := context.WithTimeout(ctx, time.Second*10)
					defer cancel()
					results, err := detector.FromData(ctx, verify, decoded.Data)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"source_type": decoded.SourceType.String(),
							"metadata":    decoded.SourceMetadata,
						}).WithError(err).Error("could not scan chunk")
						continue
					}
					for _, result := range results {
						targetChunk := chunk
						if isGitSource(chunk.SourceType) {
							copyChunk := *chunk
							targetChunk = &copyChunk
							SetLineNumber(&copyChunk, &result)
						}
						e.results <- detectors.CopyMetadata(targetChunk, result)
					}
					if len(results) > 0 {
						elasped := time.Since(start)
						detectorName := results[0].DetectorType.String()
						avgTimeI, ok := e.detectorAvgTime.Load(detectorName)
						avgTime := []time.Duration{}
						if ok {
							avgTime, ok = avgTimeI.([]time.Duration)
							if !ok {
								continue
							}
						}
						avgTime = append(avgTime, elasped)
						e.detectorAvgTime.Store(detectorName, avgTime)
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

func isGitSource(sourceType sourcespb.SourceType) bool {
	for _, i := range gitSources() {
		if i == sourceType {
			return true
		}
	}
	return false
}

func SetLineNumber(chunk *sources.Chunk, result *detectors.Result) {
	var startingLine *int64
	switch metadata := chunk.SourceMetadata.GetData().(type) {
	case *source_metadatapb.MetaData_Git:
		startingLine = &metadata.Git.Line
	case *source_metadatapb.MetaData_Github:
		startingLine = &metadata.Github.Line
	case *source_metadatapb.MetaData_Gitlab:
		startingLine = &metadata.Gitlab.Line
	case *source_metadatapb.MetaData_Bitbucket:
		startingLine = &metadata.Bitbucket.Line
	case *source_metadatapb.MetaData_Gerrit:
		startingLine = &metadata.Gerrit.Line
	}
	lines := bytes.Split(chunk.Data, []byte("\n"))

	for i, line := range lines {
		if bytes.Contains(line, result.Raw) {
			*startingLine = *startingLine + int64(i)
			return
		}
	}
	return
}
