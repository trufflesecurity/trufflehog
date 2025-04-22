package bitcoinaverage

import (
	"context"
	"encoding/json"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bitcoinaverage"}) + `\b([a-zA-Z0-9]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bitcoinaverage"}
}

type response struct {
	Msg     string `json:"msg"`
	Success bool   `json:"success"`
}

// FromData will find and optionally verify BitcoinAverage secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_BitcoinAverage,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := verifyBitcoinAverage(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BitcoinAverage
}

func (s Scanner) Description() string {
	return "BitcoinAverage is a service that provides cryptocurrency market data. BitcoinAverage API keys can be used to access and retrieve this market data."
}

// docs: https://apiv2.bitcoinaverage.com/#authentication
func verifyBitcoinAverage(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://apiv2.bitcoinaverage.com/websocket/v3/get_ticket", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("x-ba-key", key)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		apiResponse := &response{}
		if err = json.NewDecoder(resp.Body).Decode(apiResponse); err != nil {
			return false, err
		}

		if apiResponse.Success {
			return true, nil
		}

		return false, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
