package virustotal

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"virustotal"}) + `\b([a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"virustotal"}
}

// FromData will find and optionally verify VirusTotal secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_VirusTotal,
			Raw:          []byte(resMatch),
		}

		if verify {
			s1.Verified = verifyToken(ctx, client, resMatch)
			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}
		}
		results = append(results, s1)
	}

	return results, nil
}

func verifyToken(ctx context.Context, client *http.Client, token string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/metadata", nil)
	if err != nil {
		return false
	}
	req.Header.Add("x-apikey", token)

	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return false
	}
	return true
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_VirusTotal
}
