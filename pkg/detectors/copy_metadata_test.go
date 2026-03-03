package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestCopyMetadata_ChunkDataFromOriginalData(t *testing.T) {
	chunk := &sources.Chunk{
		Data:         []byte("decoded-data"),
		OriginalData: []byte("original-source-data"),
		SourceName:   "test-source",
	}
	result := Result{
		DetectorType: 1,
		Raw:          []byte("secret"),
	}

	rwm := CopyMetadata(chunk, result)

	assert.Equal(t, "original-source-data", string(rwm.ChunkData))
}

func TestCopyMetadata_ChunkDataFallsBackToData(t *testing.T) {
	chunk := &sources.Chunk{
		Data:       []byte("only-data"),
		SourceName: "test-source",
	}
	result := Result{
		DetectorType: 1,
		Raw:          []byte("secret"),
	}

	rwm := CopyMetadata(chunk, result)

	assert.Equal(t, "only-data", string(rwm.ChunkData))
}
