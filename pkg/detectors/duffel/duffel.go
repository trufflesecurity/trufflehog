package duffel

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Duffel API tokens: duffel_test_xxx or duffel_live_xxx
	keyPat = regexp.MustCompile(`(duffel_(test|live)_[a-zA-Z0-9_-]{40,60})`)
)

func (s Scanner) Keywords() []string {
	return []string{"duffel_test", "duffel_live", "duffel"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Duffel,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyDuffel(ctx, client, token)
			s1.Verified = isVerified

			if verificationErr != nil {
				s1.SetVerificationError(verificationErr, token)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyDuffel(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Only verify test tokens - live tokens should not be auto-verified
	if !strings.HasPrefix(token, "duffel_test_") {
		return false, fmt.Errorf("live token detected - skipping verification for safety")
	}

	// Duffel API endpoint - Get airlines list (public data, safe to test)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.duffel.com/air/airlines?limit=1", nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Duffel-Version", "v2")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// 200 - Valid token
		return true, nil
	case http.StatusUnauthorized:
		// 401 - Invalid token
		return false, nil
	case http.StatusForbidden:
		// 403 - Token exists but lacks permissions
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Duffel
}

func (s Scanner) Description() string {
	return "Duffel is a travel API platform for booking flights, stays, and ground transportation. Duffel API tokens can be used to access travel inventory and booking services."
}
