package trufflehogenterprise

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

	keyPat      = regexp.MustCompile(`\bthog-key-[0-9a-f]{16}\b`)
	secretPat   = regexp.MustCompile(`\bthog-secret-[0-9a-f]{32}\b`)
	hostnamePat = regexp.MustCompile(`\b[a-z]+-[a-z]+-[a-z]+\.[a-z][0-9]\.[a-z]+\.trufflehog\.org\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("thog")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)
	hostnameMatches := hostnamePat.FindAllSubmatch(data, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 1 {
			continue
		}
		resKeyMatch := bytes.TrimSpace(keyMatch[0])
		for _, secretMatch := range secretMatches {

			if len(secretMatch) != 1 {
				continue
			}
			resSecretMatch := bytes.TrimSpace(secretMatch[0])

			for _, hostnameMatch := range hostnameMatches {
				if len(hostnameMatch) != 1 {
					continue
				}

				resHostnameMatch := bytes.TrimSpace(hostnameMatch[0])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_TrufflehogEnterprise,
					Raw:          resKeyMatch,
				}

				if verify {
					endpoint := fmt.Sprintf("https://%s/api/v1/sources", string(resHostnameMatch))
					req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
					if err != nil {
						continue
					}

					req.Header.Add("Accept", "application/vnd.trufflehogenterprise+json; version=3")
					req.Header.Add("X-Thog-Secret", string(resSecretMatch))
					req.Header.Add("X-Thog-Key", string(resKeyMatch))

					res, err := client.Do(req)
					if err == nil {
						verifiedBodyResponse, err := common.ResponseContainsSubstring(res.Body, "data")
						if err != nil {
							return nil, err
						}

						defer res.Body.Close()

						if res.StatusCode >= 200 && res.StatusCode < 300 && verifiedBodyResponse {
							s1.Verified = true
						} else {
							if detectors.IsKnownFalsePositive(resSecretMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_TrufflehogEnterprise
}
