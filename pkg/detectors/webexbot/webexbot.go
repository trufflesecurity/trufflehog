package webexbot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

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
	keyPat        = regexp.MustCompile(`([a-zA-Z0-9]{64}_[a-zA-Z0-9]{4}_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"spark", "webex"}
}

// FromData will find and optionally verify Webexbot secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) > 1 {
			uniqueMatches[match[1]] = struct{}{}
		}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_WebexBot,
			Raw:          []byte(match),
			Redacted:     match[:5] + "...",
			ExtraData:    map[string]string{},
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

type response struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	NickName    string   `json:"nickName"`
	UserName    string   `json:"username"`
	Emails      []string `json:"emails"`
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://webexapis.com/v1/people/me", nil)
	if err != nil {
		return false, nil, nil
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// parse the response body to json
		var resp response
		extraData := make(map[string]string)
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return true, nil, fmt.Errorf("failed to decode response: %w", err)
		}

		extraData["type"] = resp.Type
		extraData["username"] = resp.UserName
		return true, extraData, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_WebexBot
}

func (s Scanner) Description() string {
	return "Webex bot allows applications to interact with users in Webex spaces."
}
