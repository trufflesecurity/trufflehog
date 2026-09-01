package humioingesttoken

import (
	"bytes"
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

// verifyIngestToken sends a minimal HEC event to check token validity.
//
// Ingest tokens are write-only — LogScale provides no read or validation
// endpoint that accepts them (the docs state: "ingest tokens can only be used
// to ingest data; you cannot use them to query LogScale, log in, or read any
// data"). This means every verification creates a log entry in the customer's
// repository. The event body is an empty string to minimize noise, but scans
// with many matches will produce that many entries.
//
// Response semantics: 200 means fully valid. 403 or 422 still signal a
// recognized token (blocked by IP filter / permissions, or pointing at a
// deleted repo) so both count as verified. Only 401 means the token is
// completely unknown.
func verifyIngestToken(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	endpoint, err := url.JoinPath(baseURL, "/api/v1/ingest/hec")
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(`{"event":""}`))
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
		return true, nil
	case http.StatusForbidden:
		// Token was recognized but blocked (IP filter, permission change).
		return true, nil
	case http.StatusUnprocessableEntity:
		// Token accepted but the repository can't be resolved (deleted repo).
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
