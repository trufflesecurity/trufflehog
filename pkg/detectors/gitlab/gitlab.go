package gitlab

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

type Scanner struct{ detectors.EndpointSetter }

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func (Scanner) Version() int            { return 1 }
func (Scanner) DefaultEndpoint() string { return "https://gitlab.com" }

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"gitlab"}) + `\b((?:glpat|)[a-zA-Z0-9\-=_]{20,22})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("gitlab")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		if bytes.Contains(match[0], []byte("glpat")) {
			keyString := bytes.Split(match[0], []byte(" "))
			resMatch = keyString[len(keyString)-1]
		}

		secret := detectors.Result{
			DetectorType: detectorspb.DetectorType_Gitlab,
			Raw:          match[1],
		}

		if verify {
			client := common.SaneHttpClient()
			for _, baseURL := range s.Endpoints(s.DefaultEndpoint()) {
				req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v4/user", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(resMatch)))
				res, err := client.Do(req)
				if err == nil {
					res.Body.Close()

					if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
						secret.Verified = true
					}
				}
			}
		}

		if !secret.Verified && detectors.IsKnownFalsePositive(secret.Raw, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, secret)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gitlab
}
