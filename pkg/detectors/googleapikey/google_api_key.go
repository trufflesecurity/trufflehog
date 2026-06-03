package googleapikey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Google API keys begin with "AIza" followed by exactly 35 characters from [0-9A-Za-z_-].
	keyPat = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"AIza"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GoogleApiKey
}

func (s Scanner) Description() string {
	return "Google API keys are used to authenticate requests to Google APIs and services."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllString(dataStr, -1) {
		uniqueMatches[strings.TrimSpace(match)] = struct{}{}
	}

	for key := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_GoogleApiKey,
			Raw:          []byte(key),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/google/",
			},
			SecretParts: map[string]string{"key": key},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyKey(ctx, client, key)
			r.Verified = isVerified
			for k, v := range extraData {
				r.ExtraData[k] = v
			}
			r.SetVerificationError(verificationErr, key)
		}

		results = append(results, r)
	}

	return results, nil
}

func verifyKey(ctx context.Context, client *http.Client, apiKey string) (bool, map[string]string, error) {
	verified, extraData, err := verifyBooks(ctx, client, apiKey)
	if verified || err == nil {
		return verified, extraData, err
	}

	return verifyGemini(ctx, client, apiKey)
}

func verifyBooks(ctx context.Context, client *http.Client, apiKey string) (bool, map[string]string, error) {
	u := "https://www.googleapis.com/books/v1/volumes?q=a&maxResults=1&key=" + url.QueryEscape(apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, nil, err
	}

	return classifyResponse(resp.StatusCode, body, "books")
}

func verifyGemini(ctx context.Context, client *http.Client, apiKey string) (bool, map[string]string, error) {
	const endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

	payload := []byte(`{"contents":[{"parts":[{"text":"ping"}]}],"generationConfig":{"maxOutputTokens":1}}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, nil, err
	}

	return classifyResponse(resp.StatusCode, body, "gemini")
}

func classifyResponse(statusCode int, body []byte, source string) (bool, map[string]string, error) {
	if statusCode >= 200 && statusCode < 300 {
		return true, nil, nil
	}

	lower := strings.ToLower(errorText(body))

	switch {
	case statusCode == http.StatusUnauthorized:
		return false, nil, nil

	case statusCode == http.StatusTooManyRequests:
		return true, map[string]string{
			"restriction": "rate-limited on " + source + " API",
		}, nil

	case containsAny(lower, []string{
		"api key not valid",
		"invalid api key",
		"keyinvalid",
		"api key expired",
		"invalid credentials",
	}):
		return false, nil, nil

	case containsAny(lower, []string{
		"accessnotconfigured",
		"usagelimits",
		"ratelimitexceeded",
		"dailylimitexceeded",
		"dailylimit",
		"userratelimitexceeded",
		"quotaexceeded",
		"iprefererblocked",
		"not enabled",
		"has not been used",
		"blocked",
		"forbidden",
	}):
		return true, map[string]string{
			"restriction": "key valid but restricted on " + source + " API",
		}, nil

	case statusCode == http.StatusForbidden:
		return true, map[string]string{
			"restriction": "key valid but access forbidden on " + source + " API",
		}, nil
	}

	return false, nil, fmt.Errorf("unexpected HTTP response status %d", statusCode)
}

type googleErrorBody struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
			Domain  string `json:"domain"`
			Reason  string `json:"reason"`
		} `json:"errors"`
	} `json:"error"`
}

func errorText(body []byte) string {
	var e googleErrorBody
	if err := json.Unmarshal(body, &e); err != nil {
		return string(body)
	}

	parts := []string{e.Error.Message}
	for _, sub := range e.Error.Errors {
		parts = append(parts, sub.Reason, sub.Message, sub.Domain)
	}
	return strings.Join(parts, " ")
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
