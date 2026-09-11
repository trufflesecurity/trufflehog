package dynatrace

import (
	"bytes"
	"context"
	"encoding/json"
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
	detectors.DefaultMultiPartCredentialProvider
}

var (
	_ detectors.Detector                    = (*Scanner)(nil)
	_ detectors.MultiPartCredentialProvider = (*Scanner)(nil)
)

var (
	defaultClient = common.SaneHttpClient()

	// Dynatrace tokens have the shape <prefix>.<public-id>.<secret>:
	//   prefix    = dt0[a-z][0-9]{2} (e.g. dt0c01 API/PAT token, dt0s16 platform token)
	//   public-id = 8-128 char, non-secret token identifier
	//   secret    = exactly 64 uppercase alphanumerics
	tokenPat = regexp.MustCompile(`\b(dt0[a-z][0-9]{2}\.[a-zA-Z0-9-]{8,128}\.[A-Z0-9]{64})\b`)

	// Dynatrace SaaS tenant hosts. Restricted to the real environment shapes so the
	// environment qualifier (live/dev/sprint) is preserved and hosts like www/docs.dynatrace.com
	// do not match. The "apps" subdomain is the 3rd-gen UI and is normalized away in
	// tenantToAPIHost before a request is made.
	tenantPat = regexp.MustCompile(`\b([a-z0-9-]+\.(?:live\.dynatrace|apps\.dynatrace|(?:dev|sprint)\.dynatracelabs|(?:dev|sprint)\.apps\.dynatracelabs)\.com)\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks. "dt0" is always present in a token,
// so it reliably pre-filters; the provider name alone would miss tokens in files that do not
// also contain the word "dynatrace".
func (s Scanner) Keywords() []string {
	return []string{"dt0"}
}

// uniqueMatches returns the distinct group-1 matches of pat in data.
func uniqueMatches(pat *regexp.Regexp, data string) map[string]struct{} {
	matches := make(map[string]struct{})
	for _, m := range pat.FindAllStringSubmatch(data, -1) {
		matches[m[1]] = struct{}{}
	}
	return matches
}

// FromData will find and optionally verify Dynatrace tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := uniqueMatches(tokenPat, dataStr)
	tenants := uniqueMatches(tenantPat, dataStr)

	for token := range tokens {
		// A token can only be verified against its tenant. When no tenant URL is present in the
		// chunk the token is still reported as an unverified finding.
		if len(tenants) == 0 {
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_Dynatrace,
				Raw:          []byte(token),
				Redacted:     redact(token),
				SecretParts:  map[string]string{"token": token},
			})
			continue
		}

		// Pair the token with every tenant in the chunk: a token authenticates only against its
		// own tenant, so trying all candidates is what verifies the right pairing.
		for tenant := range tenants {
			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Dynatrace,
				Raw:          []byte(token),
				RawV2:        []byte("token:" + token + " tenant:" + tenant),
				Redacted:     redact(token),
				SecretParts:  map[string]string{"token": token, "tenant": tenant},
				ExtraData:    map[string]string{"tenant": tenant},
			}

			if verify {
				verified, verificationErr := verifyToken(ctx, s.getClient(), tenant, token)
				r.Verified = verified
				// An unreachable tenant (DNS failure, timeout, etc.) is reported as a
				// verification issue rather than silently leaving the token unverified.
				r.SetVerificationError(verificationErr, token)
			}

			results = append(results, r)
		}
	}

	return results, nil
}

// redact keeps the non-secret prefix and public identifier and masks the secret segment.
func redact(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 3 {
		return token
	}
	return parts[0] + "." + parts[1] + ".********"
}

func verifyToken(ctx context.Context, client *http.Client, tenant, token string) (bool, error) {
	environment := "https://" + tenantToAPIHost(tenant) + "/api/v2/apiTokens/lookup"

	payload, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, environment, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Api-Token "+token)
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		// 200 = valid (the body is the token metadata); 403 = the token is valid but lacks the
		// scope to look itself up. Both mean the credential authenticated successfully.
		return true, nil
	case http.StatusUnauthorized:
		// The token is expired, inactive, or otherwise invalid for this tenant.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// tenantToAPIHost normalizes a discovered tenant host to the host that serves the API.
// The "apps" subdomain is the 3rd-gen UI and has only a very limited platform API:
//   - prod: apps is the UI sibling of the live API host, so swap apps -> live.
//   - dev/sprint: the qualifier is already present, so the extra apps label is dropped.
//
// The environment qualifier (live/dev/sprint) is otherwise never changed.
func tenantToAPIHost(host string) string {
	host = strings.Replace(host, ".apps.dynatrace.com", ".live.dynatrace.com", 1)
	host = strings.Replace(host, ".apps.", ".", 1)
	return host
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Dynatrace
}

func (s Scanner) Description() string {
	return "Dynatrace is a software intelligence platform for observability and application monitoring. Dynatrace API tokens, personal access tokens, and platform tokens grant programmatic access to a tenant's monitoring data and configuration."
}
