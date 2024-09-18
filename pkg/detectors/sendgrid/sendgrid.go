package sendgrid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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

	keyPat = regexp.MustCompile(`\bSG\.[\w\-]{20,24}\.[\w\-]{39,50}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"SG."}
}

// FromData will find and optionally verify Sendgrid secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[0]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SendGrid,
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
			s1.AnalysisInfo = map[string]string{"key": token}
		}

		results = append(results, s1)
	}

	return
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// Check the scopes assigned to the api key.
	// https://docs.sendgrid.com/api-reference/api-key-permissions/retrieve-a-list-of-scopes-for-which-this-user-has-access
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
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
		extraData := map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/sendgrid/",
		}

		var scopesRes scopesResponse
		if err := json.NewDecoder(res.Body).Decode(&scopesRes); err != nil {
			return false, nil, err
		}

		if len(scopesRes.Scopes) > 0 {
			extraData["scopes"] = strings.Join(scopesRes.Scopes, ",")
		}

		return true, extraData, nil
	case http.StatusUnauthorized:
		// 401 means the key is definitively invalid.
		return false, nil, nil
	case http.StatusForbidden:
		// 403 means good key but not the right scope
		return true, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type scopesResponse struct {
	Scopes []string `json:"scopes"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SendGrid
}
