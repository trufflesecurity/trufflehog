package cryptocompare

import (
	"context"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cryptocompare"}) + `\b([a-z-0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cryptocompare"}
}

// FromData will find and optionally verify CryptoCompare secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CryptoCompare,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://min-api.cryptocompare.com/data/blockchain/list?api_key="+resMatch, nil)
	if err != nil {
		return false, err
	}
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}
	bodyString := string(bodyBytes)
	errCode := strings.Contains(bodyString, `"Response":"Success"`)
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		if errCode {
			return true, nil
		}
	}

	return false, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CryptoCompare
}

func (s Scanner) Description() string {
	return "CryptoCompare is a cryptocurrency market data provider. CryptoCompare API keys can be used to access and retrieve market data."
}
