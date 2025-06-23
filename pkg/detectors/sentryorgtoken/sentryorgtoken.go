package sentryorgtoken

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
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	orgAuthTokenPat = regexp.MustCompile(`\b(sntrys_eyJ[a-zA-Z0-9=_+/]{197})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sntrys_eyJ"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SentryOrgToken
}

func (s Scanner) Description() string {
	return "Sentry is an error tracking service that helps developers monitor and fix crashes in real time. Sentry Organization Auth Tokens can be used in many places to interact with Sentry programmatically. For example, they can be used for sentry-cli, bundler plugins, or similar use cases."
}

// FromData will find and optionally verify SentryToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// find all unique org auth tokens
	var uniqueOrgTokens = make(map[string]struct{})

	for _, orgToken := range orgAuthTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueOrgTokens[orgToken[1]] = struct{}{}
	}

	for orgToken := range uniqueOrgTokens {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SentryOrgToken,
			Raw:          []byte(orgToken),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}

			isVerified, verificationErr := verifySentryOrgToken(ctx, s.client, orgToken)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, orgToken)
		}

		results = append(results, s1)
	}

	return results, nil
}

// docs: https://docs.sentry.io/account/auth-tokens/#organization-auth-tokens
func verifySentryOrgToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://sentry.io/api/0/auth/validate", nil)
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
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
