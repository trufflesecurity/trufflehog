package guru

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

	unamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"guru"}) + `\b([a-zA-Z0-9]{3,20}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,5})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"guru"}) + `\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("guru")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	unameMatches := unamePat.FindAllSubmatch(data, -1)
	keyMatches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range unameMatches {
		if len(match) != 2 {
			continue
		}

		unameMatch := bytes.TrimSpace(match[1])

		for _, secret := range keyMatches {
			if len(secret) != 2 {
				continue
			}

			keyMatch := bytes.TrimSpace(secret[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Guru,
				Raw:          unameMatch,
			}

			if verify {
				data := fmt.Sprintf("%s:%s", unameMatch, keyMatch)
				encoded := b64.StdEncoding.EncodeToString(data)

				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.getguru.com/api/v1/teams/teamId/stats", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encoded))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(keyMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Guru
}
