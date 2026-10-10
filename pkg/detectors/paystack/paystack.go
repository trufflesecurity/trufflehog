package paystack

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(`\b(sk_[a-z]+_[A-Za-z0-9]{40})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"paystack", "sk_test_", "sk_live_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	for _, match := range keyPat.FindAllStringSubmatch(string(data), -1) {
		if len(match) < 2 || match[1] == "" {
			continue
		}
		key := match[1]
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Paystack,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"key": key},
		}
		if verify {
			verified, verifyErr := verifyPaystackKey(ctx, key)
			result.Verified = verified
			if verifyErr != nil {
				result.SetVerificationError(verifyErr, key)
			}
		}
		results = append(results, result)
	}
	return results, nil
}

func verifyPaystackKey(ctx context.Context, key string) (bool, error) {
	return verifyPaystackKeyWithClient(ctx, key, client, "https://api.paystack.co/balance")
}

// verifyPaystackKeyWithClient keeps verification behavior testable without real credentials
// or network access. The endpoint is fixed in production to a documented, read-only API.
func verifyPaystackKeyWithClient(ctx context.Context, key string, httpClient *http.Client, endpoint string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		// Other responses can indicate endpoint, network policy, or account issues;
		// they do not prove that the credential is invalid.
		return false, fmt.Errorf("unexpected Paystack verification status: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Paystack
}

func (s Scanner) Description() string {
	return "Detects Paystack secret API keys"
}
