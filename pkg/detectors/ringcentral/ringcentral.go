package ringcentral

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

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ringcentral"}) + `\b([0-9A-Za-z_-]{22})\b`)
	// TODO: this domain pattern is too restrictive
	uriPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ringcentral"}) + `\b(https://www.[0-9A-Za-z_-]{1,}.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ringcentral"}
}

// FromData will find and optionally verify Ringcentral secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	uriMatches := uriPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, uriMatch := range uriMatches {
			resURI := strings.TrimSpace(uriMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RingCentral,
				Raw:          []byte(resMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://platform.devtest.ringcentral.com/restapi/oauth/authorize?response_type=code&redirect_uri=%s&client_id=%s", resURI, resMatch), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RingCentral
}

func (s Scanner) Description() string {
	return "RingCentral is a cloud-based communication system that offers messaging, video conferencing, and phone services. RingCentral API keys can be used to access and manage these services."
}
