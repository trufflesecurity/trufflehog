package onfido

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	regexp "github.com/wasilibs/go-re2"

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
	defaultClient = common.SaneHttpClientTimeOut(time.Second * 10)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(?:api_live(?:_[a-zA-Z]{2})?\.[a-zA-Z0-9-_]{11}\.[-_a-zA-Z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"api_live.", "api_live_ca.", "api_live_us."}
}

// FromData will find and optionally verify Onfido secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		// There are no capturing group in the regex, so match[0] is the only one we need.
		resMatch := strings.TrimSpace(match[0])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Onfido,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			// Determine the region code based on the prefix of resMatch
			region := "eu" // Default region
			if strings.HasPrefix(resMatch, "api_live_ca.") {
				region = "ca"
			} else if strings.HasPrefix(resMatch, "api_live_us.") {
				region = "us"
			}

			// Construct the URL using the region variable
			url := fmt.Sprintf("https://api.%s.onfido.com/v3/validate_api_token", region)
			req, err := http.NewRequestWithContext(ctx, "POST", url, nil)

			// req, err := http.NewRequestWithContext(ctx, "POST", "https://api.eu.onfido.com/v3/validate_api_token", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Token token=%s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode == 200 {
					s1.Verified = true
				} else {
					s1.Verified = false
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Onfido
}