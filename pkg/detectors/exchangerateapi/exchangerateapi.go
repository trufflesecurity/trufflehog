package exchangerateapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"exchangerate", "exchange-rate"}) + `\b([a-f0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"exchangerate", "exchange-rate"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ExchangeRateAPI
}

func (s Scanner) Description() string {
	return "An API key for determining the exchange rate of currencies"
}

// FromData will find and optionally verify ExchangeRateAPI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ExchangeRateAPI,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := verifyExchangeRateKey(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyExchangeRateKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://v6.exchangerate-api.com/v6/latest/USD", http.NoBody)
	if err != nil {
		return false, err
	}

	// authentication docs: https://www.exchangerate-api.com/docs/authentication
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
