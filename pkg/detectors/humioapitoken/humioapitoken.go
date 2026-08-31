package humioapitoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

func (Scanner) CloudEndpoint() string { return "https://cloud.us.humio.com" }

// additionalCloudEndpoints lists Humio/LogScale SaaS regions beyond the
// primary one returned by CloudEndpoint(). The CloudProvider interface
// only supports a single endpoint, so these are passed as found
// endpoints during verification to ensure tokens from any region are
// verified even when the scanned data contains no URL.
var additionalCloudEndpoints = []string{
	"https://cloud.humio.com",
}

var (
	defaultClient = common.SaneHttpClient()

	// API tokens are base62 strings with a tilde (~) separator: a 24- or
	// 32-character prefix and a fixed 44-character suffix. The tilde +
	// exact segment lengths make this format distinctive enough that no
	// PrefixRegex or surrounding-context anchor is needed.
	// Example: pHUw1oLASALFmt2ppNvwCR0Meo2nHQ15~ECViF0Ce95uIqFGSSatjKWX71EOzvkpVGSuc3zGYqJgR
	keyPat = regexp.MustCompile(`\b([A-Za-z0-9]{24}(?:[A-Za-z0-9]{8})?~[A-Za-z0-9]{44})\b`)
)

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_HumioAPIToken
}

func (s Scanner) Keywords() []string {
	// The tilde separator in the token format is distinctive but too common
	// in source code (URLs, paths, shell, bitwise ops) to use as a keyword.
	// Te regex handles precision within matched chunks.
	return []string{"humio", "logscale"}
}

func (s Scanner) Description() string {
	return "Humio/CrowdStrike Falcon LogScale is a log management platform. API tokens grant read/write access to a specific LogScale repository via the REST and GraphQL APIs."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokenMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		t := strings.TrimSpace(match[1])
		tokenMatches[t] = struct{}{}
	}

	for token := range tokenMatches {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_HumioAPIToken,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
			ExtraData:    map[string]string{"token_type": humioTokenType(token)},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			// Verification only targets known SaaS regions (US via
			// CloudEndpoint, EU via additionalCloudEndpoints) plus any
			// endpoints explicitly configured by the operator (e.g.
			// self-hosted instances). URLs discovered in scanned data are
			// not used — arbitrary hosts can return 403 for non-auth
			// reasons (WAF, CDN), causing false verification.
			//
			// Only non-nil errors overwrite lastErr so that a clean 401
			// from the wrong region doesn't erase a transient failure
			// (500, timeout) from a region that might be authoritative.
			var lastErr error
			for _, baseURL := range s.Endpoints(additionalCloudEndpoints...) {
				isVerified, vErr := verifyAPIToken(ctx, client, baseURL, token)
				r.Verified = isVerified
				if vErr != nil {
					lastErr = vErr
				}
				if isVerified {
					lastErr = nil
					r.ExtraData["endpoint"] = baseURL
					break
				}
			}
			r.SetVerificationError(lastErr, token)
		}

		results = append(results, r)
	}

	return results, nil
}

// humioTokenType classifies the token based on prefix length: 24-char
// prefixes are personal API tokens (PATs), 32-char prefixes are
// repository/view API tokens.
func humioTokenType(token string) string {
	idx := strings.Index(token, "~")
	if idx == 24 {
		return "Personal API Token"
	}
	return "Repository API Token"
}

// verifyAPIToken hits the health-json endpoint, which is read-only and
// produces no side effects. The endpoint requires authentication and
// returns cluster health status on success.
//
// Response semantics: 200 means fully valid. 403 signals a recognized token
// blocked by an IP filter, so it still counts as verified. 401 means the
// token is unknown or expired.
func verifyAPIToken(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/health-json", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		// Token was recognized but blocked (IP filter, permission change).
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
