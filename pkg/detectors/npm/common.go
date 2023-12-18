package npm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var defaultClient = common.SaneHttpClient()

type npmScanner struct {
	client *http.Client
}

// verifyToken attempts to verify a |token| by finding the associated registry URL in |data|.
// It returns three values:
//  1. whether the token is valid
//  2. data associated with the token
//  3. any errors encountered during verification
func (s npmScanner) verifyToken(ctx context.Context, data string, token string) (bool, map[string]string, error) {
	if s.client == nil {
		s.client = defaultClient
	}

	registry := findTokenRegistry(data, token)
	if registry != nil {
		// A high confidence match was found, attempt to verify the token against it.
		// e.g., |token|="s3cret" and |data| contains "//npm.company.com/:_authToken=s3cret".
		// TODO: Handle multiple high confidence matches
		return doVerification(ctx, s.client, registry, token)
	} else {
		// A high confidence match was not found.
		// Attempt to verify the token against any registries we can find.
		var (
			registries = findAllRegistryURLs(data)
			errs       = make([]error, 0, len(registries))

			verified  bool
			extraData map[string]string
			err       error
		)
		for _, registry := range registries {
			verified, extraData, err = doVerification(ctx, s.client, registry, token)
			if verified {
				return true, extraData, err
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		return false, nil, errors.Join(errs...)
	}
}

// Most repositories implement a "whoami" endpoint
// that returns the username of the authenticated user.
type whoamiResponse struct {
	Username string `json:"username"`
}

// doVerification checks whether |token| is valid for the given |registry|.
func doVerification(ctx context.Context, client *http.Client, registry *registryInfo, token string) (bool, map[string]string, error) {
	// Construct and send request.
	scheme := registry.Scheme.Prefix()
	if registry.Scheme == unknown {
		scheme = isHttps.Prefix()
	}
	reqUrl := fmt.Sprintf("%s%s/-/whoami", scheme, registry.Uri)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqUrl, nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to construct request: %s", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		// A |tls.RecordHeaderError| likely means that the server is using HTTP, not HTTPS.
		// TODO: Is it possible to handle the reverse case?
		var tlsErr tls.RecordHeaderError
		if errors.As(err, &tlsErr) && registry.Scheme == isHttps {
			r := *registry
			r.Scheme = isHttp
			return doVerification(ctx, client, &r, token)
		}
		return false, nil, fmt.Errorf("request to %s failed: %w", reqUrl, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// Handle the response.
	if res.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		whoamiRes := whoamiResponse{}
		if err := json.Unmarshal(body, &whoamiRes); err != nil {
			if json.Valid(body) {
				return false, nil, fmt.Errorf("failed to decode response %s: %w", reqUrl, err)
			} else {
				// If the response isn't JSON it's highly unlikely to be valid.
				return false, nil, nil
			}
		}

		// It is possible for the response to be `{"username": null}`, `{"username":""}`, etc.
		// While a valid token _can_ return an empty username, the registry is likely returning 200 for invalid auth.
		// TODO: Write a test for this.
		if whoamiRes.Username == "" ||
			(registry.RegistryType == nexusRepo3 && strings.HasPrefix(whoamiRes.Username, "anonymous")) ||
			(registry.RegistryType == jetbrains && whoamiRes.Username == "internal") {
			req.Header.Del("Authorization")
			res2, err := client.Do(req)
			if err != nil {
				return false, nil, fmt.Errorf("request failed for %s: %w", reqUrl, err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res2.Body.Close()

			if res2.StatusCode == http.StatusOK {
				return false, nil, nil
			}
		}

		data := map[string]string{
			"registry_type":  registry.RegistryType.String(),
			"registry_url":   registry.Uri,
			"username":       whoamiRes.Username,
			"rotation_guide": "https://howtorotate.com/docs/tutorials/npm/",
		}
		return true, data, nil
	} else if res.StatusCode == http.StatusUnauthorized ||
		(registry.RegistryType == github && res.StatusCode == http.StatusForbidden) {
		// Token is not valid.
		return false, nil, nil
	} else {
		// Here be dragons.
		return false, nil, fmt.Errorf("unexpected response status %d for %s", res.StatusCode, reqUrl)
	}
}

// firstNonEmptyMatch returns the index and value of the first non-empty match.
// If no non-empty match is found, it will return: 0, "".
func firstNonEmptyMatch(matches []string, skip int) (int, string) {
	if len(matches) < skip {
		return 0, ""
	}
	// The first index is the entire matched string.
	for i, val := range matches[skip:] {
		if val != "" {
			return i + skip, val
		}
	}
	return 0, ""
}
