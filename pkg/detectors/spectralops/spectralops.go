package spectralops

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

	// SpectralOps Personal API keys:
	// Format: spu- + 32 lowercase aplhabets or digits
	spectralTokenPat = regexp.MustCompile(
		`\b(spu-[a-z0-9]{32})\b`,
	)
)

// Keywords used for fast pre-filtering
func (s Scanner) Keywords() []string {
	return []string{"spectral", "spu"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData scans for SpectralOps API tokens and optionally verifies them
func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range spectralTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	for token := range uniqueTokens {
		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_SpectralOps,
			Raw:          []byte(token),
			RawV2:        []byte(token),
		}

		if verify {
			verified, verificationErr := verifySpectralToken(
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

func verifySpectralToken(
	ctx context.Context,
	client *http.Client,
	token string,
) (bool, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://get.spectralops.io/api/v1/users",
		http.NoBody,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

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
		// Token is invalid or revoked
		return false, nil
	default:
		return false, fmt.Errorf(
			"unexpected HTTP response status %d",
			res.StatusCode,
		)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SpectralOps
}

func (s Scanner) Description() string {
	return "SpectralOps is a DevSecOps platform for detecting secrets and misconfigurations. This detector identifies Spectral personal API tokens."
}
