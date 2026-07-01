package grafana

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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(glc_eyJ[A-Za-z0-9+\/=]{60,160})`)
)

func (s Scanner) getClient() *http.Client {
	client := s.client
	if client == nil {
		client = defaultClient
	}

	return client
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"glc_eyJ"}
}

// FromData will find and optionally verify Grafana secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Grafana,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			isVerified, verificationErr := verifyGrafanaKey(ctx, s.getClient(), resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Grafana
}

func (s Scanner) Description() string {
	return "Grafana is an open-source platform for monitoring and observability. Grafana API keys can be used to access and manage Grafana resources."
}

func verifyGrafanaKey(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://grafana.com/api/v1/tokens?region=us", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		// 200: token is valid and has permission to list tokens.
		// 403: token is valid (authenticated) but lacks permission for this
		// resource. Either way the credentials are genuine, so it's verified.
		return true, nil
	case http.StatusUnauthorized:
		// Grafana returns 401 for two very different cases that can only be
		// told apart by the response body:
		//
		//   1. A valid token that authenticated successfully but lacks the
		//      accesspolicies:read scope. The body reports a permission/scope
		//      error, e.g.:
		//        {"code":"Unauthorized","message":"invalid permission: access
		//         policy missing required scope [accesspolicies:read], ..."}
		//
		//   2. An invalid/revoked token that failed authentication, e.g.:
		//        {"code":"InvalidCredentials","message":"Token could not be parsed"}
		//
		// A permission/scope error can only be produced after authentication
		// succeeds, so use that as the positive signal. We deliberately do not
		// match the looser "Unauthorized" string because revoked tokens can
		// also surface it, which previously caused false positives.
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		body := string(bodyBytes)

		if strings.Contains(body, "invalid permission") || strings.Contains(body, "required scope") {
			return true, nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
