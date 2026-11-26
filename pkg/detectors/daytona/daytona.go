package daytona

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(dtn_[0-9a-f]{64})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"dtn_"}
}

// FromData will find and optionally verify Daytona secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Daytona,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

// verifyEndpoints lists the Daytona API hosts a key may be valid against: the
// original (v0) API and the newer (v2) API. A key is invalid only if every host rejects it.
var verifyEndpoints = []string{
	"https://app.daytona.io/api/sandbox",
	"https://api.daytona.com/sandboxes",
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	var firstErr error
	for _, endpoint := range verifyEndpoints {
		verified, err := verifyEndpoint(ctx, client, endpoint, token)
		if verified {
			return true, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// An error on any host leaves the result indeterminate rather than "not verified".
	return false, firstErr
}

func verifyEndpoint(ctx context.Context, client *http.Client, endpoint, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

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
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Daytona
}

func (s Scanner) Description() string {
	return "Daytona provides secure sandbox infrastructure for running AI-generated code. Daytona API keys can be used to create and manage sandboxes."
}
