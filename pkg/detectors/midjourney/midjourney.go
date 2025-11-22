package midjourney

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"midjourney", "mj_api", "mj-api", "midjourney_api"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MidJourney,
			Raw:          []byte(token),
			Verified:     false,
		}

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MidJourney
}

func (s Scanner) Description() string {
	return "MidJourney tokens for unofficial API access. Verification may not be available."
}

