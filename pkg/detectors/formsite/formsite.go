package formsite

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

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"formsite"}) + `\b([a-zA-Z0-9]{32})\b`)
	serverPat = regexp.MustCompile(detectors.PrefixRegex([]string{"formsite"}) + `\b(fs[0-9]{1,4})\b`)
	userPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"formsite"}) + `\b([a-zA-Z0-9]{6})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("formsite")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	// Convert all string operations to equivalent byte operations
	matches := keyPat.FindAllSubmatch(data, -1)
	serverMatches := serverPat.FindAllSubmatch(data, -1)
	userMatches := userPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, serverMatch := range serverMatches {
			if len(serverMatch) != 2 {
				continue
			}
			resServerMatch := bytes.TrimSpace(serverMatch[1])
			for _, userMatch := range userMatches {
				if len(userMatch) != 2 {
					continue
				}
				resUserMatch := bytes.TrimSpace(userMatch[1])
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Formsite,
					Raw:          resMatch,
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.formsite.com/api/v2/%s/forms", resServerMatch, resUserMatch), nil)
					if err != nil {
						continue
					}
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
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

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Formsite
}
