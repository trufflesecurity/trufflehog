package googleoauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// There is conflicting information about the expected length of access tokens.
	// 10 seems like a reasonable minimum that will weed out placeholders.
	//
	// https://cloud.google.com/docs/authentication/token-types#access
	// https://github.com/GoogleChrome/developer.chrome.com/blob/51dd7dd5d510ed85d86f5a91cb8fde50b62351c7/site/en/docs/webstore/using_webstore_api/index.md?plain=1#L95
	keyPat = regexp.MustCompile(`\b(ya29\.(?i:[a-z0-9_-]{10,}))(?:[^a-z0-9_-]|\z)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ya29."}
}

// FromData will find and optionally verify Googleoauth2 secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := make(map[string]struct{})
	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		tokens[matches[1]] = struct{}{}
	}

	for token := range tokens {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
		}

		if verify {
			if s.client == nil {
				s.client = defaultClient
			}

			verified, extraData, vErr := s.verify(ctx, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(vErr)
		}

		// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
		if !s1.Verified && detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}
	return
}

func (s Scanner) verify(ctx context.Context, token string) (bool, map[string]string, error) {
	// Based on https://stackoverflow.com/a/66957524
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="+token, nil)
	if err != nil {
		return false, nil, err
	}

	res, err := s.client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_ = res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
	}()

	if res.StatusCode == http.StatusOK {
		var token tokenInfo
		if err := json.NewDecoder(res.Body).Decode(&token); err != nil {
			return false, nil, fmt.Errorf("failed to decode response: %w", err)
		}

		extraData := map[string]string{
			"google_email":   token.Email,
			"email_verified": token.EmailVerified,
			"scope":          token.Scope,
			"access_type":    token.AccessType,
		}

		exp, err := strconv.ParseInt(token.Expiry, 10, 64)
		if err == nil {
			extraData["expires_at"] = time.Unix(exp, 0).String()
		}
		return true, extraData, nil
	} else if res.StatusCode == http.StatusBadRequest {
		var errInfo errorInfo
		if err := json.NewDecoder(res.Body).Decode(&errInfo); err != nil {
			return false, nil, fmt.Errorf("failed to decode response: %w", err)
		}

		if errInfo.Error == "Invalid Value" {
			// Definitively false.
			return false, nil, nil
		} else {
			return false, nil, fmt.Errorf("unexpected error description '%s' for %s", errInfo.Error, req.URL)
		}
	} else {
		return false, nil, fmt.Errorf("unexpected respones %d for %s", res.StatusCode, req.URL)
	}
}

type tokenInfo struct {
	Expiry        string `json:"exp"`
	Scope         string `json:"scope"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	AccessType    string `json:"access_type"`
}

// {"error_description": "Invalid Value"}
type errorInfo struct {
	Error string `json:"error_description"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GoogleOauth2
}
