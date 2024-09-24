package azurefunctionkey

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat      = regexp.MustCompile(detectors.PrefixRegex([]string{"azure"}) + `\b([a-zA-Z0-9_-]{20,56})\b={0,2}`)
	azureUrlPat = regexp.MustCompile(`\bhttps:\/\/([a-zA-Z0-9-]{2,30})\.azurewebsites\.net\/api\/([a-zA-Z0-9-]{2,30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"azure"}
}

// FromData will find and optionally verify azure secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	urlMatches := azureUrlPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		resTrim := strings.Split(strings.TrimSpace(match[0]), " ")
		resMatch := resTrim[len(resTrim)-1]
		for _, urlMatch := range urlMatches {
			resUrl := strings.TrimSpace(urlMatch[0])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AzureFunctionKey,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resUrl),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				req, err := http.NewRequestWithContext(ctx, "GET", resUrl+"?code="+resMatch, nil)
				if err != nil {
					continue
				}
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 401 {
						// The secret is determinately not verified (nothing to do)
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resMatch)
					}
				} else {
					s1.SetVerificationError(err, resMatch)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureFunctionKey
}

func (s Scanner) Description() string {
	return "Azure Functions is a serverless compute service that lets you run event-triggered code without having to explicitly provision or manage infrastructure. Azure Function Keys can be used to access and manage these functions."
}
