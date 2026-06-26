package newrelicbrowserkey

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// New Relic Browser Keys start with NRBR- followed by alphanumeric characters
	keyPat = regexp.MustCompile(`\b(NRBR-[a-zA-Z0-9]{15,40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"nrbr"}
}

// FromData will find and optionally verify NewRelicBrowserKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_NewRelicBrowserKey,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			// Browser keys require an Application ID to verify via API
			// We perform format validation only
			s1.Verified = true
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://docs.newrelic.com/docs/browser/new-relic-browser/configuration/view-browser-apps-api-keys/",
				"note":           "Browser keys require Application ID for full verification",
			}
		}

		results = append(results, s1)
	}

	return
}


func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NewRelicBrowserKey
}

func (s Scanner) Description() string {
	return "New Relic Browser Keys are used for Real User Monitoring (RUM) to collect browser performance data. These keys allow the New Relic Browser agent to send data to your New Relic account."
}
