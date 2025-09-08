package airtableoauth

import (
	"context"
	"fmt"
	"io"
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
	// The detector will attempt to match access tokens generated through the Airtable OAuth flow
	// Airtable OAuth does not support generating access tokens using client ID and key
	// Reference: https://airtable.com/developers/web/api/oauth-reference
	tokenPat = regexp.MustCompile(`\b([[:alnum:]]+\.v1\.[a-zA-Z0-9_-]+\.[a-f0-9]+)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"airtable"}
}

// FromData will find and optionally verify AirtableOAuth secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AirtableOAuth,
			Raw:          []byte(match),
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

			if s1.Verified {
				s1.AnalysisInfo = map[string]string{"token": match}
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	endpoint := "https://api.airtable.com/v0/meta/whoami"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
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
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AirtableOAuth
}

func (s Scanner) Description() string {
	return "Airtable is a cloud collaboration service that offers database-like features. Airtable OAuth tokens can be used to access and modify data within Airtable bases."
}
