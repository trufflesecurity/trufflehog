package customerio

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"customer"}) + `\b([a-z0-9A-Z]{20})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"customer"}) + `\b([a-z0-9A-Z]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"customerio"}
}

// FromData will find and optionally verify CustomerIO secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, idmatch := range idmatches {
			resIdMatch := strings.TrimSpace(idmatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CustomerIO,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				payload := strings.NewReader("name=purchase&data%5Bprice%5D=23.45&data%5Bproduct%5D=socks")

				data := fmt.Sprintf("%s:%s", resIdMatch, resMatch)
				sEnc := b64.StdEncoding.EncodeToString([]byte(data))

				req, err := http.NewRequestWithContext(ctx, "POST", "https://track.customer.io/api/v1/customers/5/events", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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
	return detectorspb.DetectorType_CustomerIO
}

func (s Scanner) Description() string {
	return "CustomerIO is a platform for sending automated emails, push notifications, and SMS messages. CustomerIO API keys can be used to interact with the CustomerIO service to manage customer data and trigger events."
}
