package salesforce

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	currentVersion = "58.0" // current Salesforce version
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	accessTokenPat = regexp.MustCompile(`\b00[a-zA-Z0-9]{13}![a-zA-Z0-9_.]{96}\b`)
	instancePat    = regexp.MustCompile(`\bhttps://[0-9a-zA-Z-\.]{1,100}\.my\.salesforce\.com\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"salesforce"}
}

// FromData will find and optionally verify Salesforce secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	instanceMatches := instancePat.FindAllStringSubmatch(dataStr, -1)
	tokenMatches := accessTokenPat.FindAllStringSubmatch(dataStr, -1)

	for _, instance := range instanceMatches {
		if len(instance) != 1 {
			continue
		}

		instanceMatch := strings.TrimSpace(instance[0])

		for _, token := range tokenMatches {
			if len(token) != 1 {
				continue
			}

			tokenMatch := strings.TrimSpace(token[0])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Salesforce,
				Raw:          []byte(tokenMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				req, err := http.NewRequestWithContext(ctx, "GET", instanceMatch+"/services/data/v"+currentVersion+"/query?q=SELECT+name+from+Account", nil)
				if err != nil {
					continue
				}
				req.Header.Set("Authorization", "Bearer "+tokenMatch)

				res, err := client.Do(req)

				if err != nil {
					// End execution, append Detector Result if request fails to prevent panic on response body checks
					s1.SetVerificationError(err, tokenMatch)
					results = append(results, s1)
					continue
				}

				verifiedBodyResponse, err := common.ResponseContainsSubstring(res.Body, "records")

				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 && verifiedBodyResponse {
					s1.Verified = true
				} else if res.StatusCode >= 200 && res.StatusCode < 300 && !verifiedBodyResponse {
					s1.Verified = false
				} else if res.StatusCode == 401 {
					s1.Verified = false
				} else {
					err = fmt.Errorf("request to %v returned status %d with error %+v", res.Request.URL, res.StatusCode, err)
					s1.SetVerificationError(err, tokenMatch)
				}

			}

			results = append(results, s1)

		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Salesforce
}
