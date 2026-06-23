package octopusapikey

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	// Keep the provider keyword close to the secret pattern to reduce false positives.
	// Octopus Deploy API keys are commonly represented as API- followed by 26 uppercase alphanumerics.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"octopus", "x-octopus-apikey"}) + `\b(API-[A-Z0-9]{26})(?:['"|\n\r\s\x60;]|$)`)
)

func (s Scanner) Keywords() []string {
	return []string{"octopus", "X-Octopus-ApiKey"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_OctopusApiKey
}

func (s Scanner) Description() string {
	return "Octopus Deploy API keys authenticate requests to Octopus REST API endpoints."
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) < 2 {
			continue
		}
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	results := make([]detectors.Result, 0, len(uniqueMatches))
	for key := range uniqueMatches {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_OctopusApiKey,
			Raw:          []byte(key),
			ExtraData: map[string]string{
				"rotation_guide": "https://octopus.com/docs/octopus-rest-api/how-to-create-an-api-key",
			},
			SecretParts: map[string]string{"key": key},
		})
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}
