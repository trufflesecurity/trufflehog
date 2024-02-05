package bitfinex

import (
	"context"
	"flag"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/bitfinexcom/bitfinex-api-go/v2/rest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// related resource https://medium.com/@Bitfinex/api-development-update-april-65fe52f84124
	apiKeyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"bitfinex"}) + `\b([A-Za-z0-9_-]{43})\b`)
	apiSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bitfinex"}) + `\b([A-Za-z0-9_-]{43})\b`)
)

var (
	api = flag.String("api", "https://api-pub.bitfinex.com/v2/", "v2 REST API URL")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bitfinex"}
}

// FromData will find and optionally verify Bitfinex secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	apiKeyMatches := apiKeyPat.FindAllStringSubmatch(dataStr, -1)
	apiSecretMatches := apiSecretPat.FindAllStringSubmatch(dataStr, -1)

	for _, apiKeyMatch := range apiKeyMatches {
		if len(apiKeyMatch) != 2 {
			continue
		}
		apiKeyRes := strings.TrimSpace(apiKeyMatch[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Bitfinex,
			Raw:          []byte(apiKeyRes),
		}

		for _, apiSecretMatch := range apiSecretMatches {
			if len(apiSecretMatch) != 2 {
				continue
			}
			apiSecretRes := strings.TrimSpace(apiSecretMatch[1])

			if apiKeyRes == apiSecretRes {
				continue
			}

			if verify {
				// thankfully official golang examples exist but you just need to dig their many repos https://github.com/bitfinexcom/bitfinex-api-go/blob/master/examples/v2/rest-orders/main.go
				key := apiKeyRes
				secret := apiSecretRes
				http.DefaultClient = client // filed https://github.com/bitfinexcom/bitfinex-api-go/issues/238 to improve this
				c := rest.NewClientWithURL(*api).Credentials(key, secret)

				isValid := true // assume valid
				_, err = c.Orders.AllHistory()
				if err != nil {
					if strings.HasPrefix(err.Error(), "POST https://") { // eg POST https://api-pub.bitfinex.com/v2/auth/r/orders/hist: 500 apikey: digest invalid (10100)
						isValid = false
					} else {
						if detectors.IsKnownFalsePositive(apiKeyRes, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}

				s1.Verified = isValid
				// If there is a valid one, we need to stop iterating now and return the valid result
				if isValid {
					break
				}
			}
		}

		// By appending resutls in the outer loop we can reduce false positives if there are multiple
		// combinations of secrets and IDs found.
		if len(apiSecretMatches) > 0 {
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bitfinex
}
