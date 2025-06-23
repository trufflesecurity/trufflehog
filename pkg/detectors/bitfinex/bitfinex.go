package bitfinex

import (
	"context"
	"flag"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/bitfinexcom/bitfinex-api-go/v2/rest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

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

	var uniqueAPIKeys, uniqueAPISecrets = make(map[string]struct{}), make(map[string]struct{})

	for _, apiKey := range apiKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPIKeys[apiKey[1]] = struct{}{}
	}

	for _, apiSecret := range apiSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPISecrets[apiSecret[1]] = struct{}{}
	}

	for apiKey := range uniqueAPIKeys {
		for apiSecret := range uniqueAPISecrets {
			// as both patterns are same, avoid verifying same string for both
			if apiKey == apiSecret {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Bitfinex,
				Raw:          []byte(apiKey),
			}

			if verify {
				isVerified, verificationErr := verifyBitfinex(apiKey, apiSecret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bitfinex
}

func (s Scanner) Description() string {
	return "Bitfinex is a cryptocurrency exchange offering various trading options. Bitfinex API keys can be used to access and manage trading accounts."
}

// docs: https://docs.bitfinex.com/docs/introduction
func verifyBitfinex(key, secret string) (bool, error) {
	// thankfully official golang examples exist but you just need to dig their many repos https://github.com/bitfinexcom/bitfinex-api-go/blob/master/examples/v2/rest-orders/main.go
	http.DefaultClient = client
	c := rest.NewClientWithURL(*api).Credentials(key, secret)

	_, err := c.Orders.AllHistory()
	if err != nil {
		if strings.HasPrefix(err.Error(), "POST https://") { // eg POST https://api-pub.bitfinex.com/v2/auth/r/orders/hist: 500 apikey: digest invalid (10100)
			return false, nil
		}
	}

	return true, nil
}
