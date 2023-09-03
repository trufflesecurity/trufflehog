package serpstack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// Ensure the Scanner satisfies the interface at compile time.
var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"serpstack"}) + `\b([a-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("serpstack")}
}

// FromData will find and optionally verify SerpStack secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SerpStack,
			Raw:          resMatch,
		}

		if verify {
			timeout := 10 * time.Second
			client.Timeout = timeout
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.serpstack.com/search?access_key=%s&query=Mcdonalds", resMatch), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err == nil {
					validResponse := bytes.Contains(bodyBytes, []byte(`search_url`)) || bytes.Contains(bodyBytes, []byte(`"info":"Access Restricted - Your current Subscription Plan does not support HTTPS Encryption."`))
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = validResponse
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}
		}
		results = append(results, s1)
	}
	return results, nil
}

// Type returns DetectorType for this Detector
func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SerpStack
}
