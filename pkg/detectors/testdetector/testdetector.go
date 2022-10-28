package testdetector

import (
	"context"

	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Detector struct{}

// Ensure the Detector satisfies the interface at compile time
var _ detectors.Detector = (*Detector)(nil)

var (

	// Make sure that your group is surrounded in boundry characters such as below to reduce false positives
	keyPat = regexp.MustCompile(`\b(test)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (d Detector) Keywords() []string {
	return []string{"test"}
}

// FromData will find and optionally verify testdetector secrets in a given set of bytes.
func (d Detector) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AdafruitIO,
			Raw:          []byte(resMatch),
		}

		if verify {
			s1.Verified = true
		}

		results = append(results, s1)
	}

	return detectors.CleanResults(results), nil
}
