package kalturasession

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"kaltura"}) + common.BuildRegex(common.HexPattern, "", 32))
	idPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"kaltura", "id"}) + common.BuildRegex("0-9", "", 7))
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"kaltura", "email"}) + `\b([a-z0-9]{4,25}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"kaltura"}
}

// FromData will find and optionally verify Kaltura secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	emailMatches := emailPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			resIdMatch := strings.TrimSpace(idMatch[1])

			for _, emailMatch := range emailMatches {
				if len(emailMatch) != 2 {
					continue
				}
				resEmailMatch := strings.TrimSpace(emailMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_KalturaSession,
					Raw:          []byte(resMatch),
				}

				if verify {
					data := url.Values{}
					data.Set("secret", resMatch)
					data.Set("userId", resEmailMatch)
					data.Set("partnerId", resIdMatch)
					data.Set("expiry", "31536000")
					encodedData := data.Encode()
					req, err := http.NewRequestWithContext(ctx, "POST", "https://www.kaltura.com/api_v3/service/session/action/start", strings.NewReader(encodedData))
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

					res, err := client.Do(req)
					if err == nil {
						bodyBytes, err := ioutil.ReadAll(res.Body)
						if err != nil {
							continue
						}

						bodyString := string(bodyBytes)
						errorResponse := strings.Contains(bodyString, `error`)

						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 && !errorResponse {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}

				results = append(results, s1)
			}
		}
	}
	return detectors.CleanResults(results), nil
}
