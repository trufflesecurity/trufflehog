package composio

import (
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

func (Scanner) CloudEndpoint() string { return "https://backend.composio.dev" }

var defaultClient = common.SaneHttpClient()

const rotationGuide = "https://docs.composio.dev/reference/api-reference/api-keys/postApiKeyRevocation"

// maxErrorBodyBytes bounds how much of an error response is read. Composio's
// error envelope is a few hundred bytes; anything larger is not one.
const maxErrorBodyBytes = 64 * 1024

// Composio issues three key types, all a fixed prefix followed by URL-safe
// nanoid characters. oak_ and uak_ contain "ak_", so every pattern requires a
// non-alphabet character (or start of input) before the prefix. The trailing
// boundary is checked in code rather than in the pattern: a consuming trailing
// group would swallow the single delimiter between two adjacent keys and drop
// the second one.
//
// Each key type authenticates through its own header and its own routes. A key
// sent under another type's header is answered with the same 401 as no header
// at all, so verification cannot share one endpoint across types: every type
// carries the cheapest read-only route it can authenticate.
type keyPattern struct {
	keyType    string
	re         *regexp.Regexp
	verifyPath string
	header     string
}

var keyPatterns = []keyPattern{
	{
		keyType:    "project",
		re:         regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(ak_[A-Za-z0-9_-]{20})`),
		verifyPath: "/api/v3/toolkits/categories",
		header:     "x-api-key",
	},
	{
		keyType:    "org",
		re:         regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(oak_[A-Za-z0-9_-]{20})`),
		verifyPath: "/api/v3/org/owner/project/list",
		header:     "x-org-api-key",
	},
	{
		keyType:    "user",
		re:         regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(uak_[A-Za-z0-9_-]{43})`),
		verifyPath: "/api/v3/org/list?limit=1",
		header:     "x-user-api-key",
	},
}

// isKeyAlphabet reports whether b can appear inside a Composio key.
func isKeyAlphabet(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

// endsAtBoundary reports whether the key ending at end is followed by end of
// input or a character that cannot be part of a key.
func endsAtBoundary(data string, end int) bool {
	return end >= len(data) || !isKeyAlphabet(data[end])
}

// Keywords are used for efficiently pre-filtering chunks. "ak_" is a substring
// of all three prefixes.
func (s Scanner) Keywords() []string {
	return []string{"ak_"}
}

// FromData finds Composio API keys in a given set of bytes and, when asked,
// verifies each one against the Composio API.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	seen := make(map[string]struct{})
	for _, pattern := range keyPatterns {
		for _, loc := range pattern.re.FindAllStringSubmatchIndex(dataStr, -1) {
			start, end := loc[2], loc[3]
			if !endsAtBoundary(dataStr, end) {
				continue
			}
			token := dataStr[start:end]
			if _, dup := seen[token]; dup {
				continue
			}
			seen[token] = struct{}{}

			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Composio,
				Raw:          []byte(token),
				SecretParts:  map[string]string{"key": token},
				ExtraData: map[string]string{
					"key_type":       pattern.keyType,
					"rotation_guide": rotationGuide,
				},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				// Only the cloud endpoint and operator-configured endpoints are
				// used; URLs found in scanned data are never called. Only
				// non-nil errors overwrite lastErr so a clean 401 from one
				// endpoint does not erase a transient failure from another.
				var lastErr error
				for _, baseURL := range s.Endpoints() {
					verified, extra, vErr := verifyMatch(ctx, client, baseURL, pattern, token)
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
				r.SetVerificationError(lastErr, token)
			}

			results = append(results, r)
		}
	}

	return results, nil
}

// apiError is the envelope every Composio API error carries. The slug is
// stable across releases; the message is human copy.
type apiError struct {
	Error struct {
		Message string `json:"message"`
		Slug    string `json:"slug"`
		Code    int    `json:"code"`
	} `json:"error"`
}

// verifyMatch sends the key on the route its type can authenticate and maps
// the answer to verified, dead, or undecided. Composio deliberately answers
// several unrelated conditions with 401, so the verdict comes from the error
// slug in the body, never from the status code alone:
//
//   - 200: live.
//   - 401 APIKey_InvalidAPIKey, APIKey_APIKeyExpired, UserApiKey_Unauthorized,
//     and HTTP_Unauthorized "Invalid x-org-api-key": the hash matched no live
//     row. Dead, no error.
//   - 401 Auth_Unauthorized naming the key's IP allowlist: the key exists and
//     works from allowlisted addresses. Live, reported with the restriction.
//   - 403 carrying the envelope: Composio only refuses with 403 after the
//     credential resolved (a scoped key without the route's permission, an
//     org-level restriction). Live, reported with the restriction.
//   - Anything else (a banned scanner address answers "Access denied", a
//     stripped header answers Auth_NoAuthProvided, a WAF page has no
//     envelope, 429, 5xx): undecided, surfaced as a verification error.
//
// The org key's dead slug HTTP_Unauthorized is shared with the banned-address
// answer, so that one branch also reads the message; a copy change there
// degrades to an undecided error, never to a wrong verdict.
func verifyMatch(ctx context.Context, client *http.Client, baseURL string, pattern keyPattern, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+pattern.verifyPath, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set(pattern.header, token)
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
		return true, nil, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		var body apiError
		if err := json.NewDecoder(io.LimitReader(res.Body, maxErrorBodyBytes)).Decode(&body); err != nil || body.Error.Slug == "" {
			return false, nil, fmt.Errorf("HTTP %d without a Composio error envelope", res.StatusCode)
		}
		return classifyRejection(res.StatusCode, body)

	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func classifyRejection(status int, body apiError) (bool, map[string]string, error) {
	slug, message := body.Error.Slug, body.Error.Message

	switch {
	case status == http.StatusUnauthorized && (slug == "APIKey_InvalidAPIKey" || slug == "APIKey_APIKeyExpired" || slug == "UserApiKey_Unauthorized"):
		return false, nil, nil

	case status == http.StatusUnauthorized && slug == "HTTP_Unauthorized" && strings.HasPrefix(message, "Invalid x-org-api-key"):
		return false, nil, nil

	case status == http.StatusUnauthorized && slug == "Auth_Unauthorized" && strings.Contains(message, "IP allowlist"):
		return true, map[string]string{"restriction": "ip_allowlist"}, nil

	case status == http.StatusForbidden && slug == "APIKey_InsufficientPermissions":
		return true, map[string]string{"restriction": "insufficient_permissions"}, nil

	case status == http.StatusForbidden:
		return true, map[string]string{"restriction": slug}, nil

	default:
		return false, nil, fmt.Errorf("HTTP %d %s did not judge the key: %s", status, slug, message)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Composio
}

func (s Scanner) Description() string {
	return "Composio is an integration platform for AI agents. Composio API keys authenticate calls that execute tools, read connected accounts and manage triggers for a project, an organization or a user."
}
