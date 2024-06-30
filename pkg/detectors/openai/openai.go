package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	regexp "github.com/wasilibs/go-re2"

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

	// The magic string T3BlbkFJ is the base64-encoded string: OpenAI
	keyPat = regexp.MustCompile(`\b(sk-(?:(?:proj|[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?)-)?[[:alnum:]]{20}T3BlbkFJ[[:alnum:]]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"T3BlbkFJ"}
}

// FromData will find and optionally verify OpenAI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OpenAI,
			Redacted:     token[:3] + "..." + token[47:],
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
	// Undocumented API
	// https://api.openai.com/v1/organizations
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/organizations", nil)
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
		var orgs orgResponse
		if err = json.NewDecoder(res.Body).Decode(&orgs); err != nil {
			return false, nil, err
		}

		org := orgs.Data[0]
		extraData := map[string]string{
			"id":          org.ID,
			"title":       org.Title,
			"user":        org.User,
			"description": org.Description,
			"role":        org.Role,
			"is_personal": strconv.FormatBool(org.Personal),
			"is_default":  strconv.FormatBool(org.Default),
			"total_orgs":  fmt.Sprintf("%d", len(orgs.Data)),
		}
		return true, extraData, nil
	case 401:
		// Invalid
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// TODO: Add secret context?? Information about access, ownership etc
type orgResponse struct {
	Data []organization `json:"data"`
}

type organization struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	User        string `json:"name"`
	Description string `json:"description"`
	Personal    bool   `json:"personal"`
	Default     bool   `json:"is_default"`
	Role        string `json:"role"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenAI
}
