package dynadot

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClientTimeOut(5 * time.Second)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dynadot"}) + `\b([a-z0-9A-Z]{30})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"dynadot"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Dynadot,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.dynadot.com/api3.xml?key=%s&command=create_contact&name=Webb&email=myemail@email.com&phonenum=8662623399&phonecc=1&address1=POBox345&city=SanMateo&zip=94401&country=US", resMatch), nil)
			if err != nil {
				s1.VerificationError = err
			} else {
				res, err := client.Do(req)
				if err != nil {
					s1.VerificationError = err
				} else {
					defer res.Body.Close()
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						s1.VerificationError = err
					} else {
						body := string(bodyBytes)
						if strings.Contains(body, "success") {
							s1.Verified = true
						} else if !strings.Contains(body, "error") {
							s1.VerificationError = fmt.Errorf("unexpected response body: %s", body)
						}
					}
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return detectors.CleanResults(results), nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dynadot
}
