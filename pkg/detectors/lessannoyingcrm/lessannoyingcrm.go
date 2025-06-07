package lessannoyingcrm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"less"}) + `\b([a-zA-Z0-9-]{57})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lessannoyingcrm"}
}

// FromData will find and optionally verify LessAnnoyingCRM secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LessAnnoyingCRM,
			Raw:          []byte(resMatch),
		}

		if verify {
			userCode := strings.Split(resMatch, "-")
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.lessannoyingcrm.com?UserCode=%s&APIToken=%s&Function=GetUserInfo", userCode, resMatch), nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.lessannoyingcrm+json; version=3")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LessAnnoyingCRM
}

func (s Scanner) Description() string {
	return "Less Annoying CRM is a customer relationship management system. The API token can be used to access and manage customer data."
}
