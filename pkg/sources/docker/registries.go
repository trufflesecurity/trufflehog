package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// defaultHTTPClient defines a shared HTTP client with timeout for all registry requests.
var defaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

// Image represents a container image or repository entry in a registry API response.
type Image struct {
	Name string `json:"name"`
}

// registryRateLimiter limits how quickly we make registry API calls across all registries.
// We allow roughly 5 requests every ~7.5 seconds (one token every 1.5s) as a simple
// safeguard against overloading upstream APIs.
var registryRateLimiter = rate.NewLimiter(rate.Every(1500*time.Millisecond), 1)

// Registry is an interface for any Docker/OCI registry implementation that can list all images under a given namespace.
type Registry interface {
	Name() string                                                       // return name of the registry
	WithRegistryToken(registryToken string)                             // set token for registry
	ListImages(ctx context.Context, namespace string) ([]string, error) // list all images
	WithClient(client *http.Client)                                     // return the HTTP client to use
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

func (d *DockerHub) WithClient(client *http.Client) {
	d.Client = client
}

// ListImages lists all images under a Docker Hub namespace using Docker Hub's API.
//
// We fetch images in fixed-size pages and keep following the "next" link until there
// are no more pages. A shared rate limiter is used so we don't accidentally hammer
// the Docker Hub API.
func (d *DockerHub) ListImages(ctx context.Context, namespace string) ([]string, error) {
	baseURL := &url.URL{
		Scheme: "https",
		Host:   "hub.docker.com",
		Path:   path.Join("v2", "namespaces", namespace, "repositories"),
	}

	query := baseURL.Query()
	query.Set("page_size", "100") // fetch images in batches of 100 per page
	baseURL.RawQuery = query.Encode()

	allImages := []string{}
	nextURL := baseURL.String()

	for {
		if err := registryRateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, http.NoBody)
		if err != nil {
			return nil, err
		}

		if d.Token != "" {
			req.Header.Set("Authorization", "Bearer "+d.Token)
		}

		client := d.Client
		if client == nil {
			client = defaultHTTPClient
		}
		resp, err := client.Do(req)
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

		// Docker Hub sometimes returns an absolute "next" URL and sometimes a
		// relative one. ResolveReference cleans that up for us and turns whatever
		// they send into a proper URL we can call.
		next, err := url.Parse(page.Next)
		if err != nil {
			return nil, err
		}
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
}

func (q *Quay) Name() string {
	return "Quay.io"
}

func (q *Quay) WithRegistryToken(registryToken string) {
	q.Token = registryToken
}

func (q *Quay) WithClient(client *http.Client) {
	q.Client = client
}

// ListImages lists all images under a Quay namespace.
// API reference:
//
//	GET https://quay.io/api/v1/repository?namespace=<namespace>&public=true&private=true&next_page=<token>
//
// We keep following next_page while has_additional is true.
func (q *Quay) ListImages(ctx context.Context, namespace string) ([]string, error) {
	quayNamespace := path.Base(namespace) // quay.io/<namespace> -> namespace
	baseURL := &url.URL{
		Scheme: "https",
		Host:   "quay.io",
		Path:   path.Join("api", "v1", "repository"),
	}

	allImages := []string{}
	nextPageToken := ""

	for {
		if err := registryRateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		u := *baseURL
		query := u.Query()
		query.Set("namespace", quayNamespace)
		query.Set("public", "true")
		query.Set("private", "true")

		// Quay's API controls page size internally; we just fetch page by page.
		if nextPageToken != "" {
			query.Set("next_page", nextPageToken)
		}
		u.RawQuery = query.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
		if err != nil {
			return nil, err
		}

		if q.Token != "" {
			req.Header.Set("Authorization", "Bearer "+q.Token)
		}

		client := q.Client
		if client == nil {
			client = defaultHTTPClient
		}
		resp, err := client.Do(req)
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

func (g *GHCR) WithClient(client *http.Client) {
	g.Client = client
}

// GHCR paginates results and includes pagination links in the HTTP Link header.
// The Link header contains URLs for "next", "prev", "first", and "last" pages.
// Example Link header:
//
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
// For GitHub Container Registry the package listing endpoint is:
//
//	GET https://api.github.com/users/{namespace}/packages?package_type=container&per_page=100
//
// The GitHub API is paginated via the Link response header.
func (g *GHCR) ListImages(ctx context.Context, namespace string) ([]string, error) {
	ghcrNamespace := path.Base(namespace) // ghcr.io/<namespace> -> namespace

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
		q.Set("per_page", "100") // fetch images in batches of 100 per page
		u.RawQuery = q.Encode()
		return u.String()
	}()

	for nextURL != "" {
		if err := registryRateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, http.NoBody)
		if err != nil {
			return nil, err
		}

		// https://stackoverflow.com/questions/72732582/using-github-packages-without-personal-access-token
		if g.Token != "" {
			req.Header.Set("Authorization", "Bearer "+g.Token)
		}
		// GitHub recommends explicitly sending the v3 media type.
		req.Header.Set("Accept", "application/vnd.github+json")

		client := g.Client
		if client == nil {
			client = defaultHTTPClient
		}
		resp, err := client.Do(req)
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

		// Determine if there's another page via the Link header.
		nextURL = parseNextLinkURL(resp.Header.Get("Link"))
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
