package mailgun

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	tokenPats = map[string]*regexp.Regexp{
		"Original MailGun Token": regexp.MustCompile(detectors.PrefixRegex([]string{"mailgun"}) + `\b([a-zA-Z-0-9]{72})\b`),
		"Key-MailGun Token":      regexp.MustCompile(`\b(key-[a-z0-9]{32})\b`),
		"Hex MailGun Token":      regexp.MustCompile(`\b([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})\b`),
	}
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("mailgun")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	for _, tokenPat := range tokenPats {
		matches := tokenPat.FindAllSubmatch(data, -1)
		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Mailgun,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.mailgun.net/v3/domains", nil)
				if err != nil {
					continue
				}

				if bytes.HasPrefix(resMatch, []byte("key-")) {
					req.SetBasicAuth("api", string(resMatch))
				} else {
					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", resMatch))
				}

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)
		}
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mailgun
}
