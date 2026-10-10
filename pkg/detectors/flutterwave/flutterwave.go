package flutterwave

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
	keyPat = regexp.MustCompile(`\b(FLWSECK(?:_TEST)?-[A-Za-z0-9]{32}-X)\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"FLWSECK", "flutterwave"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	for _, match := range keyPat.FindAllStringSubmatch(string(data), -1) {
		if len(match) < 2 || match[1] == "" {
			continue
		}
		key := match[1]
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Flutterwave,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"key": key},
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.flutterwave.com/v3/subaccounts", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
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
		// A forbidden response may mean a valid key lacks endpoint permissions.
		// Treat all other responses as indeterminate rather than invalid.
		return false, fmt.Errorf("unexpected Flutterwave verification status: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Flutterwave
}

func (s Scanner) Description() string {
	return "Detects Flutterwave secret API keys (FLWSECK format)"
}
