package engine

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// ScanBytes scans bytes from a given channel
func (e *Engine) ScanBytes(ctx context.Context, bytesChan chan []byte) {
	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		for data := range bytesChan {
			e.ChunksChan() <- &sources.Chunk{
				SourceType:     sourcespb.SourceType_SOURCE_TYPE_BYTES,
				SourceName:     "bytes",
				SourceID:       int64(sourcespb.SourceType_SOURCE_TYPE_BYTES),
				Data:           data,
				SourceMetadata: &source_metadatapb.MetaData{},
				Verify:         true,
			}
		}
	}()
}
