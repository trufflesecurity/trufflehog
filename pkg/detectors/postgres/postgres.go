package postgres

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"postgres"}) + `\b([0-9a-zA-Z]{23}_[0-9a-zA-Z]{8})\b`)
)

// find various connection strings

// postgresql://user:secret@localhost:5432/mydb
// "host=localhost dbname=publishing user=www password=foo"

// detectors.PrefixRegex([]string{"nytimes"})

//var (
//	connectionStringPats = map[string]*regexp.Regexp{
//		"KeyValue":               regexp.MustCompile(`xoxb\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
//		"":              regexp.MustCompile(`xoxp\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
//		"Slack Workspace Access Token":  regexp.MustCompile(`xoxa\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
//		"Slack Workspace Refresh Token": regexp.MustCompile(`xoxr\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
//	}
//	verifyURL = "https://slack.com/api/auth.test"
//)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"postgres://", ""}
}

// FromData will find and optionally verify Postgres secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Postgres,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			req, err := http.NewRequestWithContext(ctx, "GET", "https://eth-mainnet.g.postgres.com/v2/"+resMatch+"/getNFTs/?owner=vitalik.eth", nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				} else {
					// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}

					if res.StatusCode != 401 {
						s1.VerificationError = fmt.Errorf("request to %v returned unexpected status %d", res.Request.URL, res.StatusCode)
					}
				}
			} else {
				s1.VerificationError = err
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Postgres
}
