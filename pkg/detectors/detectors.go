package detectors

import (
	"context"

	"github.com/trufflesecurity/trufflehog/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"

	"github.com/trufflesecurity/trufflehog/pkg/sources"
)

// Detector defines and interface for scanning for and verifying secrets.
type Detector interface {
	// FromData will scan bytes for results, and optionally verify them.
	FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
	// Keywords are used for efficiently pre-filtering chunks using substring operations.
	// Use unique identifiers that are part of the secret if you can, or the provider name.
	Keywords() []string
}

type Result struct {
	// DetectorType is the type of Detector.
	DetectorType detectorspb.DetectorType
	Verified     bool
	// Raw contains the raw secret identifier data. Prefer IDs over secrets since it is used for deduping after hashing.
	Raw []byte
	// Redacted contains the redacted version of the raw secret identification data for display purposes.
	// A secret ID should be used if available.
	Redacted       string
	ExtraData      map[string]string
	StructuredData *detectorspb.StructuredData
}

type ResultWithMetadata struct {
	// SourceMetadata contains source-specific contextual information
	SourceMetadata *source_metadatapb.MetaData
	// SourceID is the ID of the source that the API uses to map secrets to specific sources.
	SourceID int64
	// SourceType is the type of Source.
	SourceType sourcespb.SourceType
	// SourceName is the name of the Source.
	SourceName string
	Result
}

func CopyMetadata(chunk *sources.Chunk, result Result) ResultWithMetadata {
	return ResultWithMetadata{
		SourceMetadata: chunk.SourceMetadata,
		SourceID:       chunk.SourceID,
		SourceType:     chunk.SourceType,
		SourceName:     chunk.SourceName,
		Result:         result,
	}
}

// CleanResults returns all verified secrets, and if there are no verified secrets,
// just one unverified secret if there are any.
func CleanResults(results []Result) []Result {
	if len(results) == 0 {
		return results
	}

	var cleaned = make([]Result, 0)

	for _, s := range results {
		if s.Verified {
			cleaned = append(cleaned, s)
		}
	}

	if len(cleaned) == 0 {
		return results[:1]
	}

	return cleaned
}
