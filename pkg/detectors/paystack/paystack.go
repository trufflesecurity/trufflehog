package paystack

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

var (
	paystackKeyPattern = regexp.MustCompile(`\b(sk_[a-z]+_[0-9a-zA-Z]{40})\b`)
	paystackClient     = common.SaneHttpClient()
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

func (s Scanner) Keywords() []string {
	return []string{"paystack", "sk_live", "sk_test"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := paystackKeyPattern.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		key := match[1]

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Paystack,
			Raw:          []byte(key),
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
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.paystack.co/balance", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")

	resp, err := paystackClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Paystack
}

func (s Scanner) Description() string {
	return "Detects Paystack API secret keys (sk_* format)"
}
