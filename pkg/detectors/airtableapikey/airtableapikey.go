package airtableapikey

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
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

	appPat = regexp.MustCompile(`(app[a-zA-Z0-9_-]{14})`) // could be part of url
	keyPat = regexp.MustCompile(`\b(key[a-zA-Z0-9_-]{14})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"airtable"}
}

// FromData will find and optionally verify AirtableApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	appMatches := appPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}
		keyRes := strings.TrimSpace(keyMatch[1])

		for _, appMatch := range appMatches {
			if len(appMatch) != 2 {
				continue
			}
			appRes := strings.TrimSpace(appMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AirtableApiKey,
				Redacted:     appRes,
				Raw:          []byte(keyRes),
				RawV2:        []byte(keyRes + appRes),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.airtable.com/v0/"+appRes+"/Projects", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", keyRes))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(keyRes, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AirtableApiKey
}
