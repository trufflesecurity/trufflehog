package googlegemini

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
	keyPat        = regexp.MustCompile(`\b(AIzaSy[A-Za-z0-9_-]{33})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string { return []string{"aizasy"} }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoogleGeminiAPIKey
}

func (s Scanner) Description() string {
	return "Google Gemini API provides access to Google's latest generative AI models for building applications that understand and generate text, images, audio, and code with high performance and low latency."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: s.Type(),
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
		// Key is valid and has access to gemini
		return true, map[string]string{"active_google_key": "true"}, nil
	case http.StatusForbidden:
		// Key is valid but does not have access to gemini
		return false, map[string]string{"active_google_key": "true"}, nil
	case http.StatusBadRequest:
		// Key is invalid (expired, revoked)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
