package pagerdutyapikey

import (
	"context"
	"fmt"
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

const verifyURL = "https://api.pagerduty.com/users"

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pagerduty", "pager_duty", "pd_", "pd-"}) + `\b(u\+[a-zA-Z0-9_+-]{18})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pagerduty", "pager_duty", "pd_", "pd-"}
}

// FromData will find and optionally verify PagerDutyApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_PagerDutyApiKey,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyPagerdutyapikey(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func verifyPagerdutyapikey(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Token %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		// Token is missing, malformed, or invalid.
		// Note that revoked (disabled) keys are treated as invalid.
		return false, nil
	case http.StatusForbidden:
		// PagerDuty returns 403 when the token authenticated successfully but
		// lacks permission for the requested resource -- e.g. a user token for
		// a restricted-role user, or a scoped OAuth token missing users.read.
		// This confirms the credential is live.
		return true, nil
	case http.StatusTooManyRequests:
		// Rate-limited. Can't determine validity; keep indeterminate for retry.
		return false, fmt.Errorf("PagerDuty rate limit reached")
	case http.StatusBadRequest:
		// Malformed request parameters. Shouldn't happen for our simple GET.
		// Not transient -- the same request will always produce the same result.
		return false, nil
	case http.StatusPaymentRequired:
		// Account lacks the pricing-plan abilities for this endpoint. PagerDuty
		// must have authenticated the token before checking plan features, so
		// the credential is live.
		return true, nil
	case http.StatusNotFound:
		// Resource not found. Unusual on the /users collection endpoint.
		// Not transient -- retrying won't make the endpoint appear.
		// Shouldn't happen in practice.
		return false, nil
	default:
		// Unknown status codes (including 5xx server errors) are potentially
		// transient, so return an error to keep the result indeterminate.
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_PagerDutyApiKey
}

func (s Scanner) Description() string {
	return "PagerDuty is an incident management platform that provides reliable notifications, automatic escalations, on-call scheduling, and other functionality to help teams detect and fix infrastructure problems quickly. PagerDuty API keys can be used to access and manage these functionalities."
}
