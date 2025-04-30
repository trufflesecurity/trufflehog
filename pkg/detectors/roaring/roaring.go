package roaring

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	clientPat = regexp.MustCompile(detectors.PrefixRegex([]string{"roaring"}) + `\b([0-9A-Za-z_-]{28})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"roaring"}) + `\b([0-9A-Za-z_-]{28})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"roaring"}
}

// FromData will find and optionally verify Roaring secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	clientMatches := clientPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, clientMatch := range clientMatches {
		resClient := strings.TrimSpace(clientMatch[1])

		for _, secretMatch := range secretMatches {
			resSecret := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Roaring,
				Raw:          []byte(resClient),
				RawV2:        []byte(resClient + resSecret),
			}

			if verify {
				data := fmt.Sprintf("%s:%s", resClient, resSecret)
				sEnc := b64.StdEncoding.EncodeToString([]byte(data))
				payload := strings.NewReader("grant_type=client_credentials")
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.roaring.io/token", payload)
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
	return detectorspb.DetectorType_Roaring
}

func (s Scanner) Description() string {
	return "Roaring credentials can be used to access the Roaring API, which provides services for high-performance, compressed bitmaps."
}
