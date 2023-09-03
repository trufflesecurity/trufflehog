package bitfinex

import (
	"bytes"
	"context"
	"net/http"
	"regexp"

	"github.com/bitfinexcom/bitfinex-api-go/v2/rest"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client       = common.SaneHttpClient()
	apiKeyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"bitfinex"}) + `\b([A-Za-z0-9_-]{43})\b`)
	apiSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bitfinex"}) + `\b([A-Za-z0-9_-]{43})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("bitfinex")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	apiKeyMatches := apiKeyPat.FindAllSubmatch(data, -1)
	apiSecretMatches := apiSecretPat.FindAllSubmatch(data, -1)

	for _, apiKeyMatch := range apiKeyMatches {
		if len(apiKeyMatch) != 2 {
			continue
		}
		apiKeyRes := bytes.TrimSpace(apiKeyMatch[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Bitfinex,
			Raw:          apiKeyRes,
		}

		for _, apiSecretMatch := range apiSecretMatches {
			if len(apiSecretMatch) != 2 {
				continue
			}
			apiSecretRes := bytes.TrimSpace(apiSecretMatch[1])

			if bytes.Equal(apiKeyRes, apiSecretRes) {
				continue
			}

			if verify {
				key := string(apiKeyRes)
				secret := string(apiSecretRes)
				http.DefaultClient = client
				c := rest.NewClient().Credentials(key, secret)

				isValid := true
				_, err = c.Orders.AllHistory()
				if err != nil {
					if bytes.HasPrefix([]byte(err.Error()), []byte("POST https://")) {
						isValid = false
					} else if detectors.IsKnownFalsePositive(apiKeyRes, detectors.DefaultFalsePositives, true) {
						continue
					}
				}

				s1.Verified = isValid
				if isValid {
					break
				}
			}
		}

		if len(apiSecretMatches) > 0 {
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bitfinex
}
