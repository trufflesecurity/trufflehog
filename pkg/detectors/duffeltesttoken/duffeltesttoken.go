package duffeltesttoken

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

type Scanner struct {
	client *http.Client
}

// Compile-time interface check
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Duffel test token pattern
	// Format: duffel_test_ + 43 alphanumeric / dash / underscore characters
	duffelTestTokenPat = regexp.MustCompile(
		`\b(duffel_test_[A-Za-z0-9_-]{43})(?:$|[^A-Za-z0-9_-])`,
	)
)

// Keywords used for fast pre-filtering
func (s Scanner) Keywords() []string {
	return []string{"duffel_test_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData scans for Duffel test tokens and optionally verifies them
func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range duffelTestTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DuffelTestToken,
			Raw:          []byte(token),
			Redacted:     token[:15] + "...",
			SecretParts: map[string]string{
				"token": token,
			},
		}

		if verify {
			verified, verificationErr := verifyDuffelToken(
				ctx,
				s.getClient(),
				token,
			)

			result.SetVerificationError(verificationErr, token)
			result.Verified = verified
		}

		results = append(results, result)
	}

	return
}

func verifyDuffelToken(
	ctx context.Context,
	client *http.Client,
	token string,
) (bool, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.duffel.com/identity/customer/users?limit=1",
		http.NoBody,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Duffel-Version", "v2")
	req.Header.Set("Accept", "application/json")

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
		return true, nil

	case http.StatusUnauthorized:
		// Token invalid or revoked
		return false, nil

	case http.StatusForbidden:
		// Token valid but insufficient permissions - treat as verified since the token is active
		return true, nil

	default:
		return false, fmt.Errorf(
			"unexpected HTTP response status %d",
			res.StatusCode,
		)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DuffelTestToken
}

func (s Scanner) Description() string {
	return "Duffel is a flight search and booking API service. Duffel test API tokens can be used to access and interact with flight search and booking APIs in test environments."
}
