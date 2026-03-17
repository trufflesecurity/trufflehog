package flutterwave

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var (
	client = common.SaneHttpClient()

	// Matches all real Flutterwave secret key formats:
	// - FLWSECK_TEST-<32chars>-X  (test keys)
	// - FLWSECK_LIVE-<32chars>-X  (live keys)
	// - FLWSECK-<32chars>-X       (legacy/generic)
	flutterwaveKeyPattern = regexp.MustCompile(`FLWSECK(?:_TEST|_LIVE)?-[0-9a-zA-Z]{32}-X`)

	keywords = []string{"flutterwave", "FLWSECK"}
)

func (s Scanner) Keywords() []string {
	return keywords
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := flutterwaveKeyPattern.FindAllString(dataStr, -1)
	for _, match := range matches {
		key := strings.TrimSpace(match)

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Flutterwave,
			Raw:          []byte(key),
		}

		if verify {
			verified, verifyErr := verifyFlutterwave(ctx, key)
			result.Verified = verified
			if verifyErr != nil {
				result.SetVerificationError(verifyErr, key)
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func verifyFlutterwave(ctx context.Context, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.flutterwave.com/v3/transactions", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key))

	resp, err := client.Do(req)
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
	return detectorspb.DetectorType_Flutterwave
}