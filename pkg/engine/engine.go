package engine

import (
	"context"
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
	detectorAvgTime map[string][]time.Duration
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
		detectorAvgTime: map[string][]time.Duration{},
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
	return e.detectorAvgTime
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
						e.results <- detectors.CopyMetadata(chunk, result)
					}
					if len(results) > 0 {
						elasped := time.Since(start)
						detectorName := results[0].DetectorType.String()
						e.detectorAvgTime[detectorName] = append(e.detectorAvgTime[detectorName], elasped)
					}
				}
			}
		}
		atomic.AddUint64(&e.chunksScanned, 1)
	}
}
