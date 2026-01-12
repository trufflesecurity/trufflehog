package googlecloudapikey

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(AIza[A-Za-z0-9_-]{35})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string { return []string{"aiza"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoogleCloudAPIKey
}

func (s Scanner) Description() string {
	return "Google Cloud API Key provides access to Google Cloud services."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_GoogleCloudAPIKey,
			Raw:          []byte(resMatch),
			Redacted:     resMatch[:8] + "...",
		}

		if verify {
			isVerified, extraData, verificationErr := s.verify(ctx, resMatch)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifies the provide google api key using the gemini /v1/models endpoint
// 200 response indicates that key is live with gemini access
// 403 indicates that key is live, but restricted or not enabled for gemini
// 400 indicates that the key is inactive (invalid, expired or rotated)
func (s Scanner) verify(ctx context.Context, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "https://generativelanguage.googleapis.com/v1/models", http.NoBody)
	if err != nil {
		return false, nil, fmt.Errorf("error constructing request: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-goog-api-key", key)

	client := s.getClient()
	res, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("error making request: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, map[string]string{"gemini_enabled": "true"}, nil
	case http.StatusForbidden:
		return true, map[string]string{"gemini_enabled": "false"}, nil
	case http.StatusBadRequest:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
