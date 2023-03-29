package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var dedupeCache = make(map[string]struct{})

func PrintGitHubActionsOutput(r *detectors.ResultWithMetadata) error {
	out := gitHubActionsOutputFormat{
		DetectorType: r.Result.DetectorType.String(),
		DecoderType:  r.Result.DecoderType.String(),
		Verified:     r.Result.Verified,
	}

	meta, err := structToMap(r.SourceMetadata.Data)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	for _, data := range meta {
		for k, v := range data {
			if k == "line" {
				if line, ok := v.(float64); ok {
					out.StartLine = int64(line)
				}
			}
			if k == "file" {
				if filename, ok := v.(string); ok {
					out.Filename = filename
				}
			}
		}
	}

	verifiedStatus := "unverified"
	if out.Verified {
		verifiedStatus = "verified"
	}

	key := fmt.Sprintf("%s:%s:%s:%s:%d", out.DecoderType, out.DetectorType, verifiedStatus, out.Filename, out.StartLine)
	h := sha256.New()
	h.Write([]byte(key))
	key = hex.EncodeToString(h.Sum(nil))
	if _, ok := dedupeCache[key]; ok {
		return nil
	}
	dedupeCache[key] = struct{}{}

	message := fmt.Sprintf("Found %s %s result 🐷🔑\n", verifiedStatus, out.DetectorType)
	if r.Result.DecoderType != detectorspb.DecoderType_PLAIN {
		message = fmt.Sprintf("Found %s %s result with %s encoding 🐷🔑\n", verifiedStatus, out.DetectorType, out.DecoderType)
	}

	fmt.Printf("::warning file=%s,line=%d,endLine=%d::%s",
		out.Filename, out.StartLine, out.StartLine, message)

	return nil
}

type gitHubActionsOutputFormat struct {
	DetectorType,
	DecoderType string
	Verified  bool
	StartLine int64
	Filename  string
}
