package postonce

import (
	"context"
	"encoding/json"
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

	// PostOnce API keys are "po_live_" followed by an 8 hex character key ID,
	// an underscore and a 48 hex character secret.
	keyPat = regexp.MustCompile(`\b(po_live_[a-f0-9]{8}_[a-f0-9]{48})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"po_live_"}
}

// FromData will find and optionally verify PostOnce secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_PostOnce,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

type errorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	// Reference: https://docs.postonce.to/api-reference/list-accounts
	// Listing connected accounts is read-only.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://postonce.to/api/public/v1/accounts", http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil, nil
	case http.StatusUnauthorized:
		// The key is unknown, revoked or expired.
		return false, nil, nil
	case http.StatusForbidden:
		// A 403 is only returned after the key has authenticated: either the key
		// lacks the accounts:read scope, or the owner's plan does not include API
		// access. In both cases the key itself is live.
		var body errorResponse
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			return false, nil, err
		}
		switch body.Error.Code {
		case "missing_scope", "plan_not_allowed":
			return true, map[string]string{"restriction": body.Error.Code}, nil
		}
		return false, nil, fmt.Errorf("unexpected 403 error code: %q", body.Error.Code)
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_PostOnce
}

func (s Scanner) Description() string {
	return "PostOnce is a social media publishing and scheduling service. PostOnce API keys can be used to list connected social accounts and to create, schedule, publish and cancel posts on them."
}
