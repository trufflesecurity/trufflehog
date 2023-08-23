package pubnubpublishkey

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

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	pubPat = regexp.MustCompile(`\b(pub-c-[0-9a-z]{8}-[0-9a-z]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
	subPat = regexp.MustCompile(`\b(sub-c-[0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sub-c-"}
}

// FromData will find and optionally verify PubNubPublishKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := pubPat.FindAllStringSubmatch(dataStr, -1)
	subMatches := subPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, subMatch := range subMatches {
			if len(subMatch) != 2 {
				continue
			}
			ressubMatch := strings.TrimSpace(subMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PubNubPublishKey,
				Raw:          []byte(resMatch),
			}

			if verify {

				req, err := http.NewRequestWithContext(ctx, "GET", "https://ps.pndsn.com/signal/"+resMatch+"/"+ressubMatch+"/0/ch1/0/%22typing_on%22?uuid=user-123", nil)
				if err != nil {
					continue
				}
				client := s.client
				if client == nil {
					client = defaultClient
				}
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 400 || res.StatusCode == 403 {
						// 403 is suggested by the API docs (https://www.pubnub.com/docs/sdks/rest-api/send-signal-to-channel)
						// 400 is what actually seems to be coming back for invalid credentials
						// There's nothing to do here, because zero values of Result are what we want
					} else {
						s1.VerificationError = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					}
				} else {
					s1.VerificationError = err
				}
			}
			// This function will check false positives for common test words, but also it will make sure the key
			// appears 'random' enough to be a real key.
			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PubNubPublishKey
}
