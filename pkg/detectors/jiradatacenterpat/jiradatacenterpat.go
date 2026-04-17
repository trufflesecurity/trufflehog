package jiradatacenterpat

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ detectors.Detector                    = (*Scanner)(nil)
	_ detectors.EndpointCustomizer          = (*Scanner)(nil)
	_ detectors.MultiPartCredentialProvider = (*Scanner)(nil)
)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// PATs are base64-encoded strings of the form <12-digit-id>:<20-random-bytes> (33 bytes, 44 chars, no padding).
	// Since the first byte is always an ASCII digit (0x30–0x39), the first base64 character is always M, N, or O.
	// This is also verified by generating 25+ tokens.
	// The trailing boundary (?:[^A-Za-z0-9+/=]|\z) is used instead of \b to correctly handle tokens ending in + or /.
	patPat = regexp.MustCompile(detectors.PrefixRegex([]string{"jira", "atlassian"}) + `\b([MNO][A-Za-z0-9+/]{43})(?:[^A-Za-z0-9+/=]|\z)`)
	urlPat = regexp.MustCompile(detectors.PrefixRegex([]string{"jira", "atlassian"}) + `(https?://[A-Za-z0-9][A-Za-z0-9.\-]*(?::\d{1,5})?)`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"jira", "atlassian"}
}

// FromData will find and optionally verify Jira Data Center PAT secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := make(map[string]struct{})
	for _, match := range patPat.FindAllStringSubmatch(dataStr, -1) {
		if isStructuralPAT(match[1]) {
			tokens[match[1]] = struct{}{}
		}
	}

	uniqueURLs := make(map[string]struct{})
	for _, match := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueURLs[match[1]] = struct{}{}
	}
	foundURLs := make([]string, 0, len(uniqueURLs))
	for url := range uniqueURLs {
		foundURLs = append(foundURLs, url)
	}
	endpoints := make(map[string]struct{})
	for _, endpoint := range s.Endpoints(foundURLs...) {
		endpoints[endpoint] = struct{}{}
	}

	for token := range tokens {
		if len(endpoints) == 0 {
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_JiraDataCenterPAT,
				Raw:          []byte(token),
				Redacted:     token[:3] + "..." + token[len(token)-3:],
				ExtraData:    map[string]string{"message": "No Jira Data Center URL was found or configured. To verify this token, set the Jira instance base URL as a custom endpoint."},
			})
			continue
		}

		for endpoint := range endpoints {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_JiraDataCenterPAT,
				Raw:          []byte(token),
				RawV2:        []byte(token + ":" + endpoint),
				Redacted:     token[:3] + "..." + token[len(token)-3:],
			}

			if verify {
				isVerified, extraData, verificationErr := verifyPAT(ctx, s.getClient(), endpoint, token)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, token)
			}

			results = append(results, s1)

			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

// verifyPAT checks whether the token is valid by calling the /rest/api/2/myself endpoint,
// which returns the currently authenticated user.
// Docs: https://developer.atlassian.com/server/jira/platform/rest/v10002/api-group-myself/#api-api-2-myself-get
func verifyPAT(ctx context.Context, client *http.Client, baseURL, token string) (bool, map[string]string, error) {
	u, err := detectors.ParseURLAndStripPathAndParams(baseURL)
	if err != nil {
		return false, nil, err
	}
	u.Path = "/rest/api/2/myself"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var result map[string]any
		extraData := map[string]string{
			"endpoint": baseURL,
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			// 200 confirms the token is valid; failing to decode only means we can't extract extra data.
			return true, extraData, nil
		}
		if name, ok := result["displayName"].(string); ok {
			extraData["display_name"] = name
		}
		if email, ok := result["emailAddress"].(string); ok {
			extraData["email_address"] = email
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

// isStructuralPAT decodes a candidate base64 string and checks that it matches
// the "<numeric id>:<random bytes>" structure used by Jira DC PATs:
// one or more ASCII digits, a colon, then at least one more byte.
func isStructuralPAT(candidate string) bool {
	raw, err := base64.StdEncoding.DecodeString(candidate)
	if err != nil {
		return false
	}
	colon := bytes.IndexByte(raw, ':')
	if colon <= 0 || colon == len(raw)-1 {
		return false
	}
	for _, b := range raw[:colon] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_JiraDataCenterPAT
}

func (s Scanner) Description() string {
	return "Jira Data Center is a self-hosted version of Jira. Personal Access Tokens (PATs) are used to authenticate API requests to Jira Data Center instances."
}
