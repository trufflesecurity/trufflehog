package stripo

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

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// JWT token
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"stripo"}) + `\b(eyJhbGciOiJIUzI1NiJ9\.[0-9A-Za-z]{130}\.[0-9A-Za-z_-]{43})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"stripo"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Stripo,
			Raw:          []byte(resMatch),
		}

		if verify {

			// API docs: https://api.stripo.email/reference/findemails
			client := s.client
			if client == nil {
				client = defaultClient
			}
			req, err := http.NewRequestWithContext(ctx, "GET", "https://stripo.email/emailgeneration/v1/emails?parameters=sortingAsc=true", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Stripo-Api-Auth", resMatch)
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Stripo
}

func (s Scanner) Description() string {
	return "Stripo is an email template builder. Stripo API keys can be used to access and modify email templates."
}
