package xai

import (
	"context"
	"encoding/json"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b(xai-[a-zA-Z0-9]{80})+\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"xai-"}
}

// FromData will find and optionally verify DeepSeek secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Xai,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, extraData, verificationErr := verifyToken(ctx, client, token)
			s1.Verified = verified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.x.ai/v1/api-key", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case 200:
		var resData response
		if err = json.NewDecoder(res.Body).Decode(&resData); err != nil {
			return false, nil, err
		}

		return true, nil, nil
	case 400:
		// Invalid
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Xai
}

func (s Scanner) Description() string {
	return "xAI, is a public-benefit corporation working in the area of artificial intelligence"
}

type response struct {
	Acls           []string `json:"acls"`
	ApiKeyBlocked  bool     `json:"api_key_blocked"`
	ApiKeyDisabled bool     `json:"api_key_disabled"`
	ApiKeyId       string   `json:"api_key_id"`
	CreateTime     string   `json:"create_time"`
	ModifiedBy     string   `json:"modified_by"`
	ModifyTime     string   `json:"modify_time"`
	Name           string   `json:"name"`
	RedactedApiKey string   `json:"redacted_api_key"`
	TeamBlocked    bool     `json:"team_blocked"`
	TeamId         string   `json:"team_id"`
	UserId         string   `json:"user_id"`
}
