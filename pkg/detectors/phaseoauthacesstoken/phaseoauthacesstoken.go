package phaseoauthacesstoken

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
	// Phrase access tokens are typically 64-character hexadecimal strings
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"phrase"}) + `\b([a-f0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"phrase"}
}

// FromData will find and optionally verify Phrase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_PhaseOAuthAcessToken,
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
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.phrase.com/v2/projects", nil)
	if err != nil {
		return false, nil, err
	}

	// Phrase uses Authorization header with "token" prefix
	req.Header.Add("Authorization", "token "+token)

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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil, nil
	case http.StatusTooManyRequests:
		return true, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PhaseOAuthAcessToken
}

func (s Scanner) Description() string {
	return "Phrase is a translation management platform for software projects. Phrase API keys can be used to access translation projects, locales, and manage translations."
}
