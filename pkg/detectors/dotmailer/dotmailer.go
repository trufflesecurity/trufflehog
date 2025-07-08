package dotmailer

import (
	"context"
	"net/http"
	"strings"
	"time"

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
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"dotmailer"}) + `\b(apiuser-[a-z0-9]{12}@apiconnector.com)\b`)
	passPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dotmailer"}) + `\b([a-zA-Z0-9\S]{8,24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dotmailer"}
}

// FromData will find and optionally verify Dotmailer secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	passMatches := passPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range passMatches {

			resPassMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Dotmailer,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resPassMatch),
			}
			if verify {
				timeout := 10 * time.Second
				client.Timeout = timeout
				req, err := http.NewRequestWithContext(ctx, "GET", "https://r3-api.dotmailer.com/v2/account-info", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(resMatch, resPassMatch)
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
	return detectorspb.DetectorType_Dotmailer
}

func (s Scanner) Description() string {
	return "Dotmailer is an email marketing automation platform. API keys can be used to access and manage email campaigns and related data."
}
