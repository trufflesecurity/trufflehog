package atlassiandatacenter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// GetDCTokenPat returns a compiled regex that matches Atlassian Data Center PATs
// (Jira DC and Confluence DC style) scoped to the given keyword prefixes.
//
// PATs are 44-char base64 strings decoding to "<numeric-id>:<random-bytes>".
// The first character is always M, N, or O because the numeric ID begins with
// an ASCII digit (0x30–0x39). The trailing boundary prevents matching substrings
// of longer base64 strings or base64-padded tokens.
//
// This does not apply to Bitbucket DC tokens, which use a BBDC- prefix format.
func GetDCTokenPat(prefixes []string) *regexp.Regexp {
	return regexp.MustCompile(
		detectors.PrefixRegex(prefixes) + `\b([MNO][A-Za-z0-9+/]{43})(?:[^A-Za-z0-9+/=]|\z)`,
	)
}

// GetURLPat returns a compiled regex that matches self-hosted Atlassian instance
// URLs (scheme + alphanumeric-starting host + optional port up to 5 digits),
// scoped to the given keyword prefixes. Callers should store the result in a
// package-level var so the regex is compiled once at init time rather than per chunk.
func GetURLPat(prefixes []string) *regexp.Regexp {
	return regexp.MustCompile(detectors.PrefixRegex(prefixes) + `(https?://[a-zA-Z0-9][a-zA-Z0-9.\-]*(?::\d{1,5})?)`)
}

// FindEndpoints extracts all URLs matching urlPat from data, passes them through
// the resolve function (typically s.Endpoints), deduplicates the results, and
// returns them as a slice with trailing slashes stripped.
func FindEndpoints(data string, urlPat *regexp.Regexp, resolve func(...string) []string) []string {
	seen := make(map[string]struct{})
	for _, m := range urlPat.FindAllStringSubmatch(data, -1) {
		seen[m[1]] = struct{}{}
	}

	raw := make([]string, 0, len(seen))
	for u := range seen {
		raw = append(raw, u)
	}

	resolved := make(map[string]struct{})
	for _, u := range resolve(raw...) {
		resolved[strings.TrimRight(u, "/")] = struct{}{}
	}

	result := make([]string, 0, len(resolved))
	for u := range resolved {
		result = append(result, u)
	}
	return result
}

// IsStructuralPAT decodes a candidate base64 string and checks that it matches
// the "<numeric id>:<random bytes>" structure used by Jira and Confluence DC PATs:
// one or more ASCII digits, a colon, then at least one more byte.
func IsStructuralPAT(candidate string) bool {
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

// MakeVerifyRequest sends a Bearer-authenticated GET request to fullURL and
// interprets the response:
//   - 200: returns (true, decoded JSON body as map or nil if unparseable, nil)
//   - 401: returns (false, nil, nil)
//   - other: returns (false, nil, error describing the unexpected status)
//
// A non-nil error is also returned for network failures.
// Callers that need fields from the response body (e.g. display name, email)
// can read them from the returned map; callers that don't need the body can
// ignore it.
func MakeVerifyRequest(ctx context.Context, client *http.Client, fullURL, token string) (bool, map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

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
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return true, body, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
