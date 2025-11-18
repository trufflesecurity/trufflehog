package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// defaultHTTPClient defines a shared HTTP client with timeout for all registry requests.
var defaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

// Image represents a container image or repository entry in a registry API response.
type Image struct {
	Name string `json:"name"`
}

// Registry is an interface for any Docker/OCI registry implementation that can list all images under a given namespace.
type Registry interface {
	Name() string                           // return name of the registry
	WithRegistryToken(registryToken string) // set token for registry
	// TODO: Handle pagination and rate limits for list images API Call
	ListImages(ctx context.Context, namespace string) ([]string, error) // list all images
}

// MakeRegistryFromNamespace returns a Registry implementation
// based on the namespace prefix (e.g. "ghcr.io/", "quay.io/").
// If no known prefix is found, DockerHub is used by default.
func MakeRegistryFromNamespace(namespace string) Registry {
	var registry Registry
	switch {
	case strings.HasPrefix(namespace, "quay.io/"): // quay.io/abc123
		registry = &Quay{}
	case strings.HasPrefix(namespace, "ghcr.io/"): // ghcr.io/abc123
		registry = &GHCR{}
	default: // default is dockerhub
		registry = &DockerHub{}
	}

	return registry
}

const (
	maxRetriesOnRateLimit = 5
	maxSleepTime          = 30 * time.Second
)

func requestWithRateLimit(ctx context.Context, method, urlStr string, headers http.Header) (*http.Response, error) {
	for attempts := 0; attempts < maxRetriesOnRateLimit; attempts++ {
		req, err := http.NewRequestWithContext(ctx, method, urlStr, http.NoBody)
		if err != nil {
			return nil, err
		}

		// Copy headers each time to avoid mutating the caller's map.
		for k, vs := range headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}

		resp, err := defaultHTTPClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		// We'll honor Retry-After if it's present, otherwise back off a little.
		retryAfter := resp.Header.Get("Retry-After")

		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		sleepFor := 5 * time.Second // 5 second default backoff

		if retryAfter != "" {
			// Retry-After can be either seconds or an HTTP date.
			if secs, err := strconv.Atoi(retryAfter); err == nil && secs >= 0 {
				sleepFor = time.Duration(secs) * time.Second
			} else if t, err := http.ParseTime(retryAfter); err == nil {
				if duration := time.Until(t); duration > 0 {
					sleepFor = duration
				}
			}
		}

		// Rely on our own max sleep time instead of Retry-After, in case it's too long.
		if sleepFor > maxSleepTime {
			sleepFor = maxSleepTime
		}

		// Respect context cancellation while sleeping.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleepFor):
		}
	}

	return nil, fmt.Errorf("rate limited (HTTP status 429) after %d attempts", maxRetriesOnRateLimit)
}

// === Docker Hub Registry ===

// DockerHub implements the Registry interface for hub.docker.com.
type DockerHub struct {
	Token string
}

// dockerhubResp models Docker Hub's /v2/namespaces/<ns>/repositories API response.
type dockerhubResp struct {
	Next    string  `json:"next"`
	Results []Image `json:"results"`
}

func (d *DockerHub) Name() string {
	return "Dockerhub"
}

func (d *DockerHub) WithRegistryToken(registryToken string) {
	d.Token = registryToken
}

// ListImages lists all images under a Docker Hub namespace using Docker Hub's API.
func (d *DockerHub) ListImages(ctx context.Context, namespace string) ([]string, error) {
	baseURL := &url.URL{
		Scheme: "https",
		Host:   "hub.docker.com",
		Path:   path.Join("v2", "namespaces", namespace, "repositories"),
	}

	allImages := []string{}
	nextURL := baseURL.String()

	headers := http.Header{}
	if d.Token != "" {
		headers.Set("Authorization", "Bearer "+d.Token)
	}

	for nextURL != "" {
		resp, err := requestWithRateLimit(ctx, http.MethodGet, nextURL, headers)
		if err != nil {
			return nil, err
		}

		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list dockerhub images: unexpected status code: %d", resp.StatusCode)
		}

		var page dockerhubResp
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}

		for _, image := range page.Results {
			allImages = append(allImages, fmt.Sprintf("%s/%s", namespace, image.Name)) // <namespace>/<image_name>
		}

		if page.Next == "" {
			break
		}

		// page.Next may be absolute or relative.
		next, err := url.Parse(page.Next)
		if err != nil {
			return nil, err
		}

		// ResolveReference handles both absolute and relative URLs.
		nextURL = baseURL.ResolveReference(next).String()
	}

	return allImages, nil
}

// === Red Hat Quay Registry ===

// Quay implements the Registry interface for Quay.io.
type Quay struct {
	Token string
}

// quayResp models the JSON structure returned by Quay's /api/v1/repository endpoint.
type quayResp struct {
	Repositories  []Image `json:"repositories"`
	HasAdditional bool    `json:"has_additional"`
	Page          int     `json:"page"`
}

func (q *Quay) Name() string {
	return "Quay.io"
}

func (q *Quay) WithRegistryToken(registryToken string) {
	q.Token = registryToken
}

// ListImages lists all images under a Quay namespace.
func (q *Quay) ListImages(ctx context.Context, namespace string) ([]string, error) {
	quayNamespace := path.Base(namespace) // quay.io/<namespace> -> namespace
	baseURL := &url.URL{
		Scheme: "https",
		Host:   "quay.io",
		Path:   path.Join("api", "v1", "repository"),
	}

	allImages := []string{}
	nextPageToken := ""

	headers := http.Header{}
	if q.Token != "" {
		headers.Set("Authorization", "Bearer "+q.Token)
	}

	for {
		u := *baseURL
		query := u.Query()
		query.Set("namespace", quayNamespace)
		query.Set("public", "true")
		if nextPageToken != "" {
			query.Set("next_page", nextPageToken)
		}
		u.RawQuery = query.Encode()

		resp, err := requestWithRateLimit(ctx, http.MethodGet, u.String(), headers)
		if err != nil {
			return nil, err
		}

		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		body, err := io.ReadAll(resp.Body)

		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list quay images: unexpected status code: %d", resp.StatusCode)
		}

		// Quay includes repositories plus pagination hints in the body.
		var page quayResp
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}

		for _, image := range page.Repositories {
			allImages = append(allImages, fmt.Sprintf("%s/%s", namespace, image.Name)) // quay.io/<namespace>/<image_name>
		}

		if !page.HasAdditional {
			break
		}

		// Newer Quay API versions may include "next_page" in the top-level JSON.
		// To support that without introducing another struct, fall back to
		// parsing it generically when HasAdditional is true.
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, err
		}
		if np, ok := raw["next_page"].(string); ok && np != "" {
			nextPageToken = np
		} else {
			// No token – stop to avoid an infinite loop.
			break
		}
	}

	return allImages, nil
}

// === GHCR Registry ===

// GHCR implements the Registry interface for GHCR.io.
type GHCR struct {
	Token string // https://github.com/github/roadmap/issues/558
}

func (g *GHCR) Name() string {
	return "ghcr.io"
}

func (g *GHCR) WithRegistryToken(registryToken string) {
	g.Token = registryToken
}

// parseNextLinkURL extracts the URL with rel="next" from a GitHub Link header, if present.
func parseNextLinkURL(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}

	parts := strings.Split(linkHeader, ",")
	for _, part := range parts {
		section := strings.Split(strings.TrimSpace(part), ";")
		if len(section) < 2 {
			continue
		}

		linkPart := strings.TrimSpace(section[0])
		if !strings.HasPrefix(linkPart, "<") || !strings.HasSuffix(linkPart, ">") {
			continue
		}
		urlStr := strings.Trim(linkPart, "<>")

		rel := ""
		for _, attr := range section[1:] {
			attr = strings.TrimSpace(attr)
			if strings.HasPrefix(attr, "rel=") {
				rel = strings.Trim(strings.TrimPrefix(attr, "rel="), "\"")
				break
			}
		}

		if rel == "next" {
			return urlStr
		}
	}

	return ""
}

// ListImages lists all images under a GHCR namespace.
func (g *GHCR) ListImages(ctx context.Context, namespace string) ([]string, error) {
	ghcrNamespace := path.Base(namespace) // ghcr.io/<namespace> -> namespace

	// Default to "users", which works for user namespaces. Organisation support
	// can be added in the future if needed.
	baseURL := &url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   path.Join("users", ghcrNamespace, "packages"),
	}

	allImages := []string{}

	nextURL := func() string {
		u := *baseURL
		q := u.Query()
		q.Set("package_type", "container")
		q.Set("per_page", "100")
		u.RawQuery = q.Encode()
		return u.String()
	}()

	headers := http.Header{}
	if g.Token != "" {
		headers.Set("Authorization", "Bearer "+g.Token)
	}
	// GitHub recommends explicitly sending the v3 media type.
	headers.Set("Accept", "application/vnd.github+json")

	for nextURL != "" {
		resp, err := requestWithRateLimit(ctx, http.MethodGet, nextURL, headers)
		if err != nil {
			return nil, err
		}

		defer func() {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to list ghcr images: unexpected status code: %d", resp.StatusCode)
		}

		// The GHCR packages list returns an array of package objects. We only
		// care about the "name" field at this layer, so reuse the Image struct.
		var page []Image
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}

		for _, image := range page {
			allImages = append(allImages, fmt.Sprintf("%s/%s", namespace, image.Name)) // ghcr.io/<namespace>/<image_name>
		}

		link := resp.Header.Get("Link")
		nextURL = parseNextLinkURL(link)
	}

	return allImages, nil
}
