package shippo

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

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Compile-time interface check
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Shippo live tokens:
	// Format: shippo_live_ + 40 hex characters
	shippoLiveTokenPat = regexp.MustCompile(
		// `\b(shippo_live_[a-f0-9]{40})\b`,
		`\b(shippo_(live|test)_[a-f0-9]{40})\b`,
	)
)

// Keywords used for fast pre-filtering
func (s Scanner) Keywords() []string {
	// return []string{"shippo_live_"}
	return []string{"shippo_live_", "shippo_test_"} // remove this line
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData scans for Shippo live API tokens and optionally verifies them
func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range shippoLiveTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Shippo,
			Raw:          []byte(token),
		}

		if verify {
			verified, verificationErr := verifyShippoToken(
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

func verifyShippoToken(
	ctx context.Context,
	client *http.Client,
	token string,
) (bool, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.goshippo.com/shippo-accounts?page=1&results=1",
		http.NoBody,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "ShippoToken "+token)

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
	case http.StatusUnauthorized, http.StatusForbidden:
		// Token invalid or revoked
		return false, nil
	default:
		return false, fmt.Errorf(
			"unexpected HTTP response status %d",
			res.StatusCode,
		)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Shippo
}

func (s Scanner) Description() string {
	return "Shippo is a shipping API platform. This detector identifies Shippo live API tokens."
}
