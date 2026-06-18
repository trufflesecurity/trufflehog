package shippolivetoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	// apiBaseURL exists for deterministic local verification tests.
	apiBaseURL string
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

const defaultShippoAPIBaseURL = "https://api.goshippo.com"

var (
	defaultClient = common.SaneHttpClient()

	// Shippo live tokens are documented with `shippo_live_` prefix and a 40-char hex suffix.
	// This follows open-source scanner patterns while staying strict on token shape.
	tokenPat = regexp.MustCompile(`\b(shippo_live_[a-f0-9]{40})(?:['"|\n\r\s\x60;]|$)`)
)

func (s Scanner) Keywords() []string {
	return []string{"shippo_live_", "ShippoToken", "shippo"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ShippoLiveToken
}

func (s Scanner) Description() string {
	return "Shippo live API tokens authorize shipping operations and label purchases in production Shippo accounts."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) < 2 {
			continue
		}
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	client := s.getClient()
	for token := range uniqueMatches {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
			ExtraData: map[string]string{
				"rotation_guide": "https://support.goshippo.com/hc/en-us/articles/360026412791-Managing-Your-API-Tokens-in-Shippo",
			},
		}

		if verify {
			isVerified, verificationErr := verifyToken(ctx, client, s.getAPIBaseURL(), token)
			r.Verified = isVerified
			r.SetVerificationError(verificationErr, token)
		}

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) getAPIBaseURL() string {
	if strings.TrimSpace(s.apiBaseURL) != "" {
		return strings.TrimSpace(s.apiBaseURL)
	}
	return defaultShippoAPIBaseURL
}

func verifyToken(ctx context.Context, client *http.Client, apiBaseURL, token string) (bool, error) {
	base, err := url.Parse(apiBaseURL)
	if err != nil {
		return false, err
	}
	base.Path = path.Join(base.Path, "addresses")
	q := base.Query()
	q.Set("results", "1")
	base.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "ShippoToken "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
