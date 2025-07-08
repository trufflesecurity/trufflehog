package siteleaf

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

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"siteleaf"}) + `\b([0-9Aa-z]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"siteleaf"}) + `\b([0-9Aa-z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"siteleaf"}
}

// FromData will find and optionally verify Siteleaf secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idmatches {
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Siteleaf,
				Raw:          []byte(resMatch),
			}

			if verify {

				data := fmt.Sprintf("%s:%s", resIdMatch, resMatch)
				sEnc := b64.StdEncoding.EncodeToString([]byte(data))
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.siteleaf.com/v2/sites", nil)
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
	return detectorspb.DetectorType_Siteleaf
}

func (s Scanner) Description() string {
	return "Siteleaf is a content management system (CMS) designed for managing websites. Siteleaf API keys can be used to access and modify site content and settings."
}
