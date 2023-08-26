package graphcms

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b(ey[a-zA-Z0-9]{73}.ey[a-zA-Z0-9]{365}.[a-zA-Z0-9_-]{683})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"graph"}) + `\b([a-z0-9]{25})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("graphcms")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_GraphCMS,
				Raw:          resMatch,
			}

			if verify {
				payload := strings.NewReader(`{users {id name}}`)
				req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://api-ap-northeast-1.graphcms.com/v2/%s/master", string(resIdMatch)), payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/graphql")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(resMatch)))

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			if !s1.Verified {
				if detectors.IsKnownFalsePositive(s1.Raw, detectors.DefaultFalsePositives, true) {
					continue
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GraphCMS
}
