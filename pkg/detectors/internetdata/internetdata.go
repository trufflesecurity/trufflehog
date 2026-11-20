package internetdata

import (
	"cmp"
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
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

func (Scanner) CloudEndpoint() string { return "https://api.internetdata.io" }

var defaultClient = common.SaneHttpClient()

// getClient returns the client verification requests go through. The
// VerificationClient wrap attaches the operator's access token when --verifier
// points at an auth-protected endpoint.
func (s Scanner) getClient() *http.Client {
	return s.VerificationClient(cmp.Or(s.client, defaultClient))
}

const rotationGuide = "https://docs.internetdata.io/api/api-keys/accountRotateApikey"

// maxBodyBytes bounds how much of a response is read. Both the entitlement
// answer and the error envelope are well under a kilobyte.
const maxBodyBytes = 64 * 1024

// A key is "mk_", an 8-character lowercase hex prefix, "_", and 32 base64url
// characters. The secret part can contain "_" and "-", so the pattern requires
// a character outside that alphabet (or start of input) before the key, and the
// trailing boundary is checked in code: a consuming trailing group would
// swallow the single delimiter between two adjacent keys and drop the second.
var keyPat = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(mk_[0-9a-f]{8}_[A-Za-z0-9_-]{32})`)

// isKeyAlphabet reports whether b can appear inside a key's secret part.
func isKeyAlphabet(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

// endsAtBoundary reports whether the key ending at end is followed by end of
// input or a character that cannot be part of a key.
func endsAtBoundary(data string, end int) bool {
	return end >= len(data) || !isKeyAlphabet(data[end])
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"mk_"}
}

// FromData finds InternetData API keys in a given set of bytes and, when asked,
// verifies each one against the InternetData API.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	seen := make(map[string]struct{})
	for _, loc := range keyPat.FindAllStringSubmatchIndex(dataStr, -1) {
		start, end := loc[2], loc[3]
		if !endsAtBoundary(dataStr, end) {
			continue
		}
		key := dataStr[start:end]
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_InternetData,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"key": key},
			ExtraData:    map[string]string{"rotation_guide": rotationGuide},
		}

		if verify {
			client := s.getClient()

			// Only the cloud endpoint and operator-configured endpoints are
			// used; URLs found in scanned data are never called. Only non-nil
			// errors overwrite lastErr so a clean 401 from one endpoint does not
			// erase a transient failure from another.
			var lastErr error
			for _, baseURL := range s.Endpoints() {
				verified, extra, vErr := verifyKey(ctx, client, baseURL, key)
				r.Verified = verified
				if vErr != nil {
					lastErr = vErr
				}
				if verified {
					lastErr = nil
					r.ExtraData["endpoint"] = baseURL
					for k, v := range extra {
						r.ExtraData[k] = v
					}
					break
				}
			}
			r.SetVerificationError(lastErr, key)
		}

		results = append(results, r)
	}

	return results, nil
}

// The error strings the entitlement endpoint answers with. They are part of
// its published contract (https://docs.internetdata.io/api).
const (
	errKeyInvalid     = "invalid API key"
	errKeyRevoked     = "API key revoked"
	errKeyExpired     = "API key expired"
	errSourceNotAllow = "source address not allowed for this API key"
)

type apiError struct {
	Error string `json:"error"`
}

type entitlement struct {
	Plan struct {
		Name string `json:"name"`
	} `json:"plan"`
}

// verifyKey asks the entitlement endpoint what the key is entitled to. The call
// is read-only and spends none of the key's lookups.
//
//   - 200: live; the plan's name is reported.
//   - 401 "invalid API key", "API key revoked", "API key expired": dead.
//   - 403 "source address not allowed for this API key": the key is live but
//     restricted to the CIDRs its owner allowed.
//   - Anything else (429, 5xx, a body without the error envelope): undecided,
//     surfaced as a verification error.
func verifyKey(ctx context.Context, client *http.Client, baseURL, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/v1/entitlement", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Accept", "application/json")

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
		var body entitlement
		if err := json.NewDecoder(io.LimitReader(res.Body, maxBodyBytes)).Decode(&body); err == nil && body.Plan.Name != "" {
			return true, map[string]string{"plan": body.Plan.Name}, nil
		}
		return true, nil, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		var body apiError
		if err := json.NewDecoder(io.LimitReader(res.Body, maxBodyBytes)).Decode(&body); err != nil || body.Error == "" {
			return false, nil, fmt.Errorf("HTTP %d without an InternetData error body", res.StatusCode)
		}
		switch {
		case res.StatusCode == http.StatusUnauthorized &&
			(body.Error == errKeyInvalid || body.Error == errKeyRevoked || body.Error == errKeyExpired):
			return false, nil, nil
		case res.StatusCode == http.StatusForbidden && body.Error == errSourceNotAllow:
			return true, map[string]string{"restriction": "ip_allowlist"}, nil
		default:
			return false, nil, fmt.Errorf("HTTP %d did not judge the key: %s", res.StatusCode, body.Error)
		}

	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_InternetData
}

func (s Scanner) Description() string {
	return "InternetData is an IP address, ASN and domain data API. InternetData " +
		"API keys authenticate lookups and database downloads, and spend the " +
		"plan of the organization that owns them."
}
