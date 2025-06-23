package clickhelp

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
	serverPat = regexp.MustCompile(`\b([0-9A-Za-z]{3,20}.try.clickhelp.co)\b`)
	emailPat  = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"clickhelp"}) + `\b([0-9A-Za-z]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"clickhelp"}
}

// FromData will find and optionally verify Clickhelp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	serverMatches := serverPat.FindAllStringSubmatch(dataStr, -1)
	emailMatches := emailPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range serverMatches {
		resServer := strings.TrimSpace(match[1])

		for _, emailMatch := range emailMatches {
			resEmail := strings.TrimSpace(emailMatch[1])
			for _, keyMatch := range keyMatches {
				resKey := strings.TrimSpace(keyMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ClickHelp,
					Raw:          []byte(resServer),
					RawV2:        []byte(resServer + resEmail),
				}

				if verify {
					data := fmt.Sprintf("%s:%s", resEmail, resKey)
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/api/v1/projects", resServer), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ClickHelp
}

func (s Scanner) Description() string {
	return "ClickHelp is a documentation tool that allows users to create and manage online documentation. ClickHelp API keys can be used to access and modify documentation data."
}
