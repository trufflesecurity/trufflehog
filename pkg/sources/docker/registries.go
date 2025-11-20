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
	Name() string                                                       // return name of the registry
	WithRegistryToken(registryToken string)                             // set token for registry
	ListImages(ctx context.Context, namespace string) ([]string, error) // list all images
	WithClient() *http.Client                                           // return the HTTP client to use
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
	maxRetriesOnRateLimit = 5                // maximum number of retries on HTTP 429 responses
	maxSleepTime          = 30 * time.Second // maximum allowed sleep time between retries
	initialBackoff        = 1 * time.Second  // initial backoff time before retrying
)

func requestWithRateLimit(ctx context.Context, client *http.Client, method, urlStr string, headers http.Header) (*http.Response, error) {
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

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		// Honor Retry-After if it's present, otherwise back off a little.
		retryAfter := resp.Header.Get("Retry-After")

		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		sleepFor := initialBackoff * (1 << attempts) // Exponentially increase backoff time

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
	Token  string
	Client *http.Client
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

func (d *DockerHub) WithClient() *http.Client {
	if d != nil && d.Client != nil {
		return d.Client
	}
	return defaultHTTPClient
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
		resp, err := requestWithRateLimit(ctx, d.WithClient(), http.MethodGet, nextURL, headers)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		discardBody(resp)
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
	Token  string
	Client *http.Client
}

// quayResp models the JSON structure returned by Quay's /api/v1/repository endpoint.
type quayResp struct {
	Repositories  []Image `json:"repositories"`
	HasAdditional bool    `json:"has_additional"`
	NextPage      string  `json:"next_page"`
	Page          int     `json:"page"`
}

func (q *Quay) Name() string {
	return "Quay.io"
}

func (q *Quay) WithRegistryToken(registryToken string) {
	q.Token = registryToken
}

func (q *Quay) WithClient() *http.Client {
	if q != nil && q.Client != nil {
		return q.Client
	}
	return defaultHTTPClient
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

	// Loop through paginated results that is handled via the "next_page" query parameter
	// Reference: https://docs.redhat.com/en/documentation/red_hat_quay/3.10/html/use_red_hat_quay/using_the_red_hat_quay_api#example_for_pagination
	for {
		u := *baseURL
		query := u.Query()
		query.Set("namespace", quayNamespace)
		query.Set("public", "true")
		query.Set("private", "true")
		if nextPageToken != "" {
			query.Set("next_page", nextPageToken)
		}
		u.RawQuery = query.Encode()

		resp, err := requestWithRateLimit(ctx, q.WithClient(), http.MethodGet, u.String(), headers)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		discardBody(resp)
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

		if !page.HasAdditional || page.NextPage == "" {
			break
		}
		nextPageToken = page.NextPage
	}

	return allImages, nil
}

// === GHCR Registry ===

// GHCR implements the Registry interface for GHCR.io.
type GHCR struct {
	Token  string // https://github.com/github/roadmap/issues/558
	Client *http.Client
}

func (g *GHCR) Name() string {
	return "ghcr.io"
}

func (g *GHCR) WithRegistryToken(registryToken string) {
	g.Token = registryToken
}

func (g *GHCR) WithClient() *http.Client {
	if g != nil && g.Client != nil {
		return g.Client
	}
	return defaultHTTPClient
}

// GHCR paginates results and includes pagination links in the HTTP Link header.
// The Link header contains URLs for "next", "prev", "first", and "last" pages.
// Example Link header:
// <https://api.github.com/user/abc/packages?package_type=container&per_page=100&page=2>; rel="next",
// <https://api.github.com/user/abc/packages?package_type=container&per_page=100&page=5>; rel="last"
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
		resp, err := requestWithRateLimit(ctx, g.WithClient(), http.MethodGet, nextURL, headers)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(resp.Body)
		discardBody(resp)
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

		// Check Link header for next page URL.
		link := resp.Header.Get("Link")
		nextURL = parseNextLinkURL(link)
	}

	return allImages, nil
}

// Function to discard response body
func discardBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
