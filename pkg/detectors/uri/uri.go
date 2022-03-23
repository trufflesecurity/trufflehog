package uri

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	allowKnownTestSites bool
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b[a-zA-Z]{1,10}:?\/\/[-.%\w{}]{1,50}:([-.%\S]{3,50})@[-.%\w\/:]+\b`)
)

type proxyRes struct {
	Verified bool `json:"verified"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"http"}
}

func allowlistedProtos(scheme string) bool {
	allowlisted := []string{"http", "https", "mongodb", "redis", "ftp"}
	for _, s := range allowlisted {
		if s == scheme {
			return true
		}
	}
	return false
}

// FromData will find and optionally verify URI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	//Prevent SSRF "https://us-central1-ssrfproxy.cloudfunctions.net/ssrfproxy-6d96c399-74bb-4299-b49d-c1c870277eb9"
	//TODO add as config option
	//TODO extend to other http outbound calls in other areas of code
	ssrfProtectorURL := "https://us-central1-ssrfproxy.cloudfunctions.net/ssrfproxy-6d96c399-74bb-4299-b49d-c1c870277eb9"

	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		if !s.allowKnownTestSites {
			if strings.Contains(match[0], "httpbin.org") {
				continue
			}
			if strings.Contains(match[0], "httpwatch.com") {
				continue
			}
		}

		token := match[0]
		password := match[1]

		parsedURL, err := url.Parse(token)
		if err != nil {
			continue
		}
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}
		if !allowlistedProtos(parsedURL.Scheme) {
			continue
		}

		redact := strings.TrimSpace(strings.Replace(token, password, strings.Repeat("*", len(password)), -1))

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_URI,
			Raw:          []byte(token),
			Redacted:     redact,
		}

		if verify {
			client := common.SaneHttpClient()
			// whitelist protocols

			// Assume a 200 response is a valid credential
			postValues := map[string]string{"protocol": parsedURL.Scheme, "credentialed_uri": token}
			jsonValue, _ := json.Marshal(postValues)
			req, err := http.NewRequestWithContext(ctx, "POST", ssrfProtectorURL, bytes.NewBuffer(jsonValue))
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err != nil {
				// log.WithError(err).Warn("Error in http post to SSRF proxy")
				continue
			}
			defer res.Body.Close()
			result := proxyRes{}
			body, err := ioutil.ReadAll(res.Body)
			if len(body) == 0 || err != nil {
				continue
			}
			err = json.Unmarshal(body, &result)
			if err != nil {
				// log.WithField("body", string(body)).WithError(err).Debug("Error decoding SSRF proxy response")
				continue
			}
			if result.Verified {
				s.Verified = true
			}
		}

		if !s.Verified {
			if detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, false) {
				continue
			}
		}

		results = append(results, s)
	}

	return
}
