package lob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

	// Secret keys are a live_/test_ prefix followed by 35 lowercase hex characters. Publishable keys
	// ((live|test)_pub_ + 31 hex) are excluded, as they are intended to be embedded in client-side code.
	keyPat = regexp.MustCompile(`\b((live|test)_[a-f0-9]{35})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"live_", "test_"}
}

// FromData will find and optionally verify Lob secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	uniqueMatches := make(map[string]struct{})
	for _, match := range matches {
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for resMatch := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Lob,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
			ExtraData: map[string]string{
				"environment": resMatch[:4], // live or test
			},
		}

		if verify {
			verified, err := s.verify(ctx, resMatch)
			s1.Verified = verified
			s1.SetVerificationError(err)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) verify(ctx context.Context, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.lob.com/v1/us_verifications", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, "")
	client := s.getClient()
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()
	switch res.StatusCode {
	case http.StatusUnprocessableEntity:
		// 422 indicates key is active but request body is invalid
		return true, nil
	case http.StatusForbidden:
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			return false, errors.New("invalid API response")
		}
		switch body.Error.Code {
		case "billing_address_required", "payment_method_unverified", "feature_limit_reached":
			// The key authenticated and it is the account, not the key, that is rejected.
			return true, nil
		case "invalid_api_key":
			return false, nil
		default:
			return false, fmt.Errorf("unexpected error code: <%s> in the API response body", body.Error.Code)
		}
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Lob
}

func (s Scanner) Description() string {
	return "Lob is a service for automating the creation and sending of letters, checks, and postcards. Lob API keys can be used to access and manage these services."
}
