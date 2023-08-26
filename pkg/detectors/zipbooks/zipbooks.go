package zipbooks

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

	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
	pwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"zipbooks", "password"}) + `\b([a-zA-Z0-9!=@#$%^]{8,})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("zipbooks")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	emailMatches := emailPat.FindAllSubmatch(data, -1)
	pwordMatches := pwordPat.FindAllSubmatch(data, -1)

	for _, match := range emailMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		for _, pwordMatch := range pwordMatches {
			if len(pwordMatch) != 2 {
				continue
			}
			resPword := bytes.TrimSpace(pwordMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_ZipBooks,
				Raw:          resMatch,
			}

			if verify {
				payload := bytes.NewReader([]byte(fmt.Sprintf(`{"email": "%s", "password": "%s"}`, string(resMatch), string(resPword))))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.zipbooks.com/v2/auth/login", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
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
	return detectorspb.DetectorType_ZipBooks
}
