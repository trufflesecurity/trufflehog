package resend

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

// GET /api-keys verifies both Resend permission tiers with a single
// read-only request:
//   - full_access    -> 200
//   - sending_access -> 401 with body {"name":"restricted_api_key"}
//
// See https://resend.com/docs/api-reference/api-keys/list-api-keys and
// https://resend.com/docs/api-reference/errors.
const verifyURL = "https://api.resend.com/api-keys"

var (
	defaultClient = common.SaneHttpClient()

	// Resend API keys: prefix `re_`, 8 chars of base58,
	// underscore, then 24 chars from the same alphabet.
	keyPat = regexp.MustCompile(`\b(re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"re_"}
}

// FromData will find and optionally verify Resend secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Resend,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyMatch(ctx, client, token)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

type resendError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	extraData := map[string]string{
		"rotation_guide": "https://resend.com/docs/dashboard/api-keys/introduction",
	}

	switch res.StatusCode {
	case http.StatusOK:
		// Active key with `full_access` permission.
		extraData["permission"] = "full_access"
		return true, extraData, nil

	case http.StatusUnauthorized:
		// Resend returns 401 for two distinct cases. We must look at the
		// error name to tell them apart:
		//   - restricted_api_key: active `sending_access` key trying to
		//     reach a non-send route. The key is real and can send mail.
		//   - missing_api_key:    no Authorization header (should not
		//     happen here since we set one above).
		var body resendError
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			return false, nil, nil
		}
		if body.Name == "restricted_api_key" {
			extraData["permission"] = "sending_access"
			return true, extraData, nil
		}
		return false, nil, nil

	case http.StatusBadRequest, http.StatusForbidden:
		// 400 validation_error: unknown, malformed, or soft-deleted key.
		// 403 suspended_api_key / restricted_api_key ("not active"):
		//     the key exists but is already disabled; no rotation needed.
		return false, nil, nil

	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Resend
}

func (s Scanner) Description() string {
	return "Resend is an email API for transactional and marketing email. Resend API keys can be used to send email, manage domains and audiences, and access other resources on the account."
}
