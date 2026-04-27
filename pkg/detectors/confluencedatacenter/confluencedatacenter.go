package confluencedatacenter

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
	client *http.Client
}

var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
)

func (Scanner) CloudEndpoint() string { return "" }

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	keywords = []string{"confluence", "atlassian", "wiki"}

	// 44-char base64 PAT; decoded form must match the structural check below.
	tokenPat = regexp.MustCompile(detectors.PrefixRegex(keywords) + `\b([MNO][A-Za-z0-9+/]{43})(?:[^A-Za-z0-9+/=]|\z)`)

	// Self-hosted instance URL: scheme + host + optional port. Keyword-scoped
	// so unrelated URLs in the same chunk don't get paired with tokens.
	urlPat = regexp.MustCompile(detectors.PrefixRegex(keywords) + `\b(https?://[a-zA-Z0-9.\-]+(?::\d+)?)\b`)

	invalidHosts = simple.NewCache[struct{}]()
	errNoHost    = errors.New("no such host")
)

func (s Scanner) Keywords() []string {
	return keywords
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ConfluenceDataCenter
}

func (s Scanner) Description() string {
	return "Confluence Data Center is Atlassian's self-hosted wiki product. Personal Access Tokens (PATs) authenticate via Bearer auth against the REST API and grant access scoped to the issuing user."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// isStructuralPAT decodes a candidate base64 string and checks that it matches
// the "<numeric id>:<random bytes>" structure used by Confluence DC PATs:
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

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, m := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		if _, seen := uniqueTokens[m[1]]; seen {
			continue
		}
		if isStructuralPAT(m[1]) {
			uniqueTokens[m[1]] = struct{}{}
		}
	}
	if len(uniqueTokens) == 0 {
		return nil, nil
	}

	foundURLs := make([]string, 0)
	for _, m := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		foundURLs = append(foundURLs, m[1])
	}
	uniqueURLs := make(map[string]struct{})
	for _, endpoint := range s.Endpoints(foundURLs...) {
		uniqueURLs[strings.TrimRight(endpoint, "/")] = struct{}{}
	}

	// Filter hosts cached as unreachable from prior calls once up front.
	// invalidHosts may also grow during this call (see the verify branch
	// below); those are skipped lazily inside the inner loop.
	liveURLs := make([]string, 0, len(uniqueURLs))
	for u := range uniqueURLs {
		if !invalidHosts.Exists(u) {
			liveURLs = append(liveURLs, u)
		}
	}

	for token := range uniqueTokens {
		emitted := false
		for _, baseURL := range liveURLs {
			if invalidHosts.Exists(baseURL) {
				continue
			}

			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_ConfluenceDataCenter,
				Raw:          []byte(token),
				SecretParts: map[string]string{
					"token": token,
					"url":   baseURL,
				},
				RawV2: []byte(fmt.Sprintf("%s:%s", token, baseURL)),
				ExtraData: map[string]string{
					"base_url": baseURL,
				},
			}

			if verify {
				isVerified, vErr := verifyPAT(ctx, s.getClient(), baseURL, token)
				r.Verified = isVerified
				if vErr != nil {
					if errors.Is(vErr, errNoHost) {
						invalidHosts.Set(baseURL, struct{}{})
					}
					r.SetVerificationError(vErr, token)
				}
			}

			results = append(results, r)
			emitted = true
		}

		if !emitted {
			// No reachable URL in context — emit an unverified token-only
			// result and annotate why we couldn't verify.
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_ConfluenceDataCenter,
				Raw:          []byte(token),
				SecretParts:  map[string]string{"token": token},
				RawV2:        []byte(token),
				ExtraData: map[string]string{
					"verification_note": "no reachable Confluence Data Center URL found in context; token reported unverified",
				},
			})
		}
	}

	return results, nil
}

func verifyPAT(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/rest/api/user/current"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		// Auth header outright rejected — unambiguously an invalid credential.
		return false, nil
	default:
		// 403 included: /rest/api/user/current should always be readable by a
		// valid PAT, so a Forbidden here signals something unexpected rather
		// than a definitively invalid token.
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
