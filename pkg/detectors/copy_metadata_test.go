package detectors

import (
	"testing"

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

	if string(rwm.ChunkData) != "original-source-data" {
		t.Errorf("ChunkData = %q, want %q", rwm.ChunkData, "original-source-data")
	}
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

	if string(rwm.ChunkData) != "only-data" {
		t.Errorf("ChunkData = %q, want %q", rwm.ChunkData, "only-data")
	}
}
