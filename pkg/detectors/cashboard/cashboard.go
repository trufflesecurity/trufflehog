package cashboard

import (
	"context"
	b64 "encoding/base64"
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
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"cashboard"}) + `\b([0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3})\b`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cashboard"}) + `\b([0-9a-z]{1,})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cashboard"}
}

// FromData will find and optionally verify Cashboard secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	userMatches := userPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, userMatch := range userMatches {
			resUser := strings.TrimSpace(userMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Cashboard,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resUser),
			}

			if verify {
				data := fmt.Sprintf("%s:%s", resUser, resMatch)
				sEnc := b64.StdEncoding.EncodeToString([]byte(data))
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.cashboardapp.com/account.xml", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))

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
	return detectorspb.DetectorType_Cashboard
}

func (s Scanner) Description() string {
	return "Cashboard is a financial management service. Cashboard credentials can be used to access and manage financial data and accounts."
}
