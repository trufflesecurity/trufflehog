package humioingesttoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	// UUID-format ingest token anchored to Humio/LogScale context via PrefixRegex
	// to avoid false positives on bare UUIDs from unrelated systems.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"humio", "logscale"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_HumioIngestToken
}

func (s Scanner) Keywords() []string {
	return []string{"humio", "logscale"}
}

func (s Scanner) Description() string {
	return "Humio/CrowdStrike Falcon LogScale is a log management platform. Ingest tokens allow sending log data into a specific LogScale repository."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokenMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		t := strings.TrimSpace(match[1])
		if detectors.StringShannonEntropy(t) < 3 {
			continue
		}
		tokenMatches[t] = struct{}{}
	}

	for token := range tokenMatches {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_HumioIngestToken,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
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
				isVerified, vErr := verifyIngestToken(ctx, client, baseURL, token)
				r.Verified = isVerified
				if vErr != nil {
					lastErr = vErr
				}
				if isVerified {
					lastErr = nil
					r.ExtraData = map[string]string{"endpoint": baseURL}
					break
				}
			}
			r.SetVerificationError(lastErr, token)
		}

		results = append(results, r)
	}

	return results, nil
}

// verifyIngestToken posts intentionally invalid JSON to the structured ingest
// endpoint to check whether the token is recognized without writing data.
//
// Ingest tokens are write-only — LogScale provides no read or validation
// endpoint that accepts them. The docs state: "ingest tokens can only be used
// to ingest data; you cannot use them to query LogScale, log in, or read any
// data." Sending valid data would create a log entry in the customer's
// repository on every verification, so we exploit the auth-before-parse
// ordering: if the token is valid the server rejects the malformed body with
// 400, and if the token is invalid it rejects with 401 or 403 — all before
// any data is committed.
//
// Response semantics per the LogScale Ingest API docs:
//   - 400:          token valid, payload malformed → verified (no data written)
//   - 401 or 403:   "authorization token is incorrect" → not verified
//   - 429:          rate limited → transient, return error for retry
//   - 5xx:          server error → transient, return error for retry
//   - other 4xx:    unexpected → not verified, no error
func verifyIngestToken(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	endpoint, err := url.JoinPath(baseURL, "/api/v1/ingest/humio-structured")
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader("invalid"))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

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
		// Server accepted the token and (unexpectedly) the payload.
		return true, nil
	case http.StatusBadRequest:
		// Token was accepted, server tried to parse the body and rejected it.
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	case http.StatusTooManyRequests:
		return false, fmt.Errorf("rate limited (HTTP %d)", res.StatusCode)
	default:
		if res.StatusCode >= 500 {
			return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		}
		// Any other 4xx (404, 405, 422, etc.) is ambiguous — treat as
		// definitively unverified rather than a transient failure.
		return false, nil
	}
}
