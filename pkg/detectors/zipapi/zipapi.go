package zipapi

import (
	"bytes"
	"context"
	b64 "encoding/base64"
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

	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"zipapi"}) + `\b([0-9a-z]{32})\b`)
	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
	pwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zipapi"}) + `\b([a-zA-Z0-9!=@#$%^]{7,})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("zipapi")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)
	pwordMatches := pwordPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, emailMatch := range emailMatches {
			if len(emailMatch) != 2 {
				continue
			}
			resEmail := bytes.TrimSpace(emailMatch[1])
			for _, pwordMatch := range pwordMatches {
				if len(pwordMatch) != 2 {
					continue
				}
				resPword := bytes.TrimSpace(pwordMatch[1])
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZipAPI,
					Raw:          resMatch,
				}
				if verify {
					data := append(resEmail, []byte(":")...)
					data = append(data, resPword...)
					sEnc := b64.StdEncoding.EncodeToString(data)
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://service.zipapi.us/zipcode/90210/?X-API-KEY=%s", string(resMatch)), nil)
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
	return detectorspb.DetectorType_ZipAPI
}
