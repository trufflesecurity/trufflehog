package ngc

import (
	"context"
	"encoding/base64"
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
	// keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ngc"}) + `\b([[:alnum:]]{26}:[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12})\b`)
	keyPat1 = regexp.MustCompile(`\b([[:alnum:]]{84})\b`)
	keyPat2 = regexp.MustCompile(`\b([[:alnum:]]{26}:[[:alnum:]]{8}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{4}-[[:alnum:]]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ngc"}
}

// FromData will find and optionally verify NGC secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat1.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		decode, _ := base64.StdEncoding.DecodeString(resMatch)

		containsKey := keyPat2.MatchString(string(decode))
		if containsKey {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_NGC,
				Raw:          []byte(resMatch),
			}

			if verify {
				key := "Basic " + string(base64.StdEncoding.EncodeToString([]byte("$oauthtoken:"+resMatch)))
				req, err := http.NewRequestWithContext(ctx, "GET", "https://authn.nvidia.com/token?service=ngc", nil)
				if err != nil {
					continue
				}
				req.Header = http.Header{
					"accept":        {"*/*"},
					"Authorization": {key},
				}
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
	return detectorspb.DetectorType_NGC
}

func (s Scanner) Description() string {
	return "Nvidia's API for AI related things"
}
