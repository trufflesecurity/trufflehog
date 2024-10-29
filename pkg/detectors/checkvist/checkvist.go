package checkvist

import (
	"context"
	"net/http"
	"net/url"
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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"checkvist"}) + `\b([0-9a-zA-Z]{14})\b`)
	emailPat = regexp.MustCompile(detectors.PrefixRegex([]string{"checkvist"}) + common.EmailPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"checkvist"}
}

// FromData will find and optionally verify Checkvist secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	uniqueEmailMatches := make(map[string]struct{})
	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmailMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for emailMatch := range uniqueEmailMatches {
		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Checkvist,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + emailMatch),
			}

			if verify {
				payload := url.Values{}
				payload.Add("username", emailMatch)
				payload.Add("remote_key", resMatch)

				req, err := http.NewRequestWithContext(ctx, "GET", "https://checkvist.com/auth/login.json?version=2", strings.NewReader(payload.Encode()))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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
	return detectorspb.DetectorType_Checkvist
}

func (s Scanner) Description() string {
	return "Checkvist is an online task management tool. The credentials found can be used to access and manage tasks and data within Checkvist."
}
