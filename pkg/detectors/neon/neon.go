package neon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

const (
	authURL     = "https://console.neon.tech/api/v2/auth"
	maxAuthBody = 1 << 16
)

var (
	defaultClient = common.SaneHttpClient()

	// Newly created Neon API keys are prefixed with napi_ so scanners can find them.
	// https://neon.com/docs/changelog/2025-01-31
	keyPat = regexp.MustCompile(`\b(napi_[a-zA-Z0-9]{32,128})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"napi_"}
}

// FromData will find and optionally verify Neon control-plane API keys
// (personal, organization, and project-scoped) in a given set of bytes.
// Keys created before the napi_ prefix are not detected.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Neon,
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
			s1.SetVerificationError(verificationErr, match)
			if len(extraData) > 0 {
				s1.ExtraData = extraData
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// GET /auth is Neon's whoami for the credentials on the request, including
	// personal, organization, and project-scoped API keys.
	// https://neon.com/docs/reference/api/users
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Accept", "application/json")

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
		// Determinate success: key is live. Capture identity fields when present.
		extra := map[string]string{}
		body, err := io.ReadAll(io.LimitReader(res.Body, maxAuthBody))
		if err != nil {
			return true, extra, nil
		}
		var payload struct {
			AuthMethod string `json:"auth_method"`
			AccountID  string `json:"account_id"`
		}
		if json.Unmarshal(body, &payload) == nil {
			if payload.AuthMethod != "" {
				extra["auth_method"] = payload.AuthMethod
			}
			if payload.AccountID != "" {
				extra["account_id"] = payload.AccountID
				if strings.HasPrefix(payload.AccountID, "org-") {
					extra["org_id"] = payload.AccountID
				}
			}
		}
		return true, extra, nil
	case http.StatusUnauthorized:
		// Determinate failure: key is invalid/revoked. No error object.
		return false, nil, nil
	default:
		// Indeterminate: unexpected status (rate limit, 5xx, 403, etc).
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Neon
}

func (s Scanner) Description() string {
	return "Neon is a serverless Postgres platform. Personal, organization, and project-scoped API keys authenticate to the Neon control plane and can list projects, reveal or reset database passwords, and create or delete branches."
}
