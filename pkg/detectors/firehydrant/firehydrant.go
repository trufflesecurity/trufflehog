package firehydrant

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

	// FireHydrant API keys (formerly "bot tokens") are "fhb-" followed by 32 lowercase hex characters.
	// The API reference documents them as "Bearer fhb-...": https://docs.firehydrant.com/reference/ping
	keyPat = regexp.MustCompile(`\b(fhb-[a-f0-9]{32})\b`)

	// Authenticated, read-only connectivity check: https://docs.firehydrant.com/reference/ping
	verifyURL = "https://api.firehydrant.io/v1/ping"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"fhb-"}
}

// FromData will find and optionally verify FireHydrant secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_FireHydrant,
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

// pongResponse is the subset of GET /v1/ping (PongEntity) used for ExtraData.
type pongResponse struct {
	Actor *struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"actor"`
	Organization *struct {
		Name string `json:"name"`
	} `json:"organization"`
}

// verifyMatch calls the authenticated, read-only ping endpoint, which returns the actor
// and organization the token belongs to.
func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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
		var pong pongResponse
		if err := json.NewDecoder(res.Body).Decode(&pong); err != nil {
			// The token is valid even if the body is unexpected.
			return true, nil, nil
		}
		extraData := map[string]string{}
		if pong.Actor != nil {
			if pong.Actor.Name != "" {
				extraData["actor_name"] = pong.Actor.Name
			}
			if pong.Actor.Type != "" {
				extraData["actor_type"] = pong.Actor.Type
			}
		}
		if pong.Organization != nil && pong.Organization.Name != "" {
			extraData["organization"] = pong.Organization.Name
		}
		if len(extraData) == 0 {
			extraData = nil
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		// Invalid or expired key: {"error":"The bearer token you provided is invalid or expired."}
		// 403 is left indeterminate, since a valid key with limited permissions could receive it.
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_FireHydrant
}

func (s Scanner) Description() string {
	return "FireHydrant is an incident management platform. FireHydrant API keys can read and change incidents, runbooks, services and other incident data."
}
