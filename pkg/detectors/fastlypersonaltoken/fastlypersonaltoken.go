package fastlypersonaltoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"fastly"}) + `\b([A-Za-z0-9_-]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"fastly"}
}

type token struct {
	TokenID   string `json:"id"`
	UserID    string `json:"user_id"`
	ExpiresAt string `json:"expires_at"`
	Scope     string `json:"scope"`
}

// FromData will find and optionally verify FastlyPersonalToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueMatches = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[matches[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FastlyPersonalToken,
			Raw:          []byte(match),
		}

		if verify {
			extraData, verified, verificationErr := verifyFastlyApiToken(ctx, match)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FastlyPersonalToken
}

func (s Scanner) Description() string {
	return "Fastly is a content delivery network (CDN) and cloud service provider. Fastly personal tokens can be used to authenticate API requests to Fastly services."
}

func verifyFastlyApiToken(ctx context.Context, apiToken string) (map[string]string, bool, error) {
	// api-docs: https://www.fastly.com/documentation/reference/api/auth-tokens/user/
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.fastly.com/tokens/self", nil)
	if err != nil {
		return nil, false, err
	}

	// add api key in the header
	req.Header.Add("Fastly-Key", apiToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var self token
		if err = json.NewDecoder(resp.Body).Decode(&self); err != nil {
			return nil, false, err
		}

		// capture token details in the map
		extraData := map[string]string{
			// token id is the alphanumeric string uniquely identifying a token
			"token_id": self.TokenID,
			// user id is the alphanumeric string uniquely identifying the user
			"user_id": self.UserID,
			// expires at is time-stamp (UTC) of when the token will expire
			"token_expires_at": self.ExpiresAt,
			// token scope is space-delimited list of authorization scope of the token
			"token_scope": self.Scope,
		}

		// if expires at is empty which mean token is set to never expire, add 'Never' as the value
		if extraData["token_expires_at"] == "" {
			extraData["token_expires_at"] = "never"
		}

		return extraData, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// as per fastly documentation: An HTTP 401 response is returned on an expired token. An HTTP 403 response is returned on an invalid access token.
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)

	}
}
