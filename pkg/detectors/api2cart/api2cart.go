package api2cart

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"api2cart"}) + `\b([0-9a-f]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"api2cart"}
}

// FromData will find and optionally verify Api2Cart secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Api2Cart,
			Raw:          []byte(key),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyApi2CartKey(ctx, client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyApi2CartKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.api2cart.com/v1.1/account.cart.list.json?api_key=%s", key), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}

		var result Response
		if err := json.Unmarshal(body, &result); err != nil {
			return false, err
		}
		if result.ReturnCode == 0 {
			return true, nil
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
	return false, nil
}

type Response struct {
	ReturnCode int `json:"return_code"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Api2Cart
}

func (s Scanner) Description() string {
	return "Api2Cart is a unified shopping cart data interface that allows interaction with multiple shopping cart platforms. Api2Cart API keys can be used to access and manipulate shopping cart data."
}
