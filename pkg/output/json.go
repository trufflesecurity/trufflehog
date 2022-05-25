package output

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

func PrintJSON(r *detectors.ResultWithMetadata) {
	v := &struct {
		// SourceMetadata contains source-specific contextual information.
		SourceMetadata *source_metadatapb.MetaData
		// SourceID is the ID of the source that the API uses to map secrets to specific sources.
		SourceID int64
		// SourceType is the type of Source.
		SourceType sourcespb.SourceType
		// SourceName is the name of the Source.
		SourceName string
		// DetectorType is the type of Detector.
		DetectorType detectorspb.DetectorType
		// DetectorName is the string name of the DetectorType.
		DetectorName string
		Verified     bool
		// Raw contains the raw secret identifier data. Prefer IDs over secrets since it is used for deduping after hashing.
		Raw []byte
		// Redacted contains the redacted version of the raw secret identification data for display purposes.
		// A secret ID should be used if available.
		Redacted       string
		ExtraData      map[string]string
		StructuredData *detectorspb.StructuredData
	}{
		SourceMetadata: r.SourceMetadata,
		SourceID:       r.SourceID,
		SourceType:     r.SourceType,
		SourceName:     r.SourceName,
		DetectorType:   r.DetectorType,
		DetectorName:   r.DetectorType.String(),
		Verified:       r.Verified,
		Raw:            r.Raw,
		Redacted:       r.Redacted,
		ExtraData:      r.ExtraData,
		StructuredData: r.StructuredData,
	}
	out, err := json.Marshal(v)
	if err != nil {
		logrus.WithError(err).Fatal("could not marshal result")
	}
	fmt.Println(string(out))
}
