package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
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
}

// MakeRegistryFromNamespace returns a Registry implementation
// based on the namespace prefix (e.g. "ghcr.io/", "quay.io/").
// If no known prefix is found, DockerHub is used by default.
func MakeRegistryFromNamespace(namespace string) Registry {
	var registry Registry
	switch {
	case strings.HasPrefix(namespace, "quay.io"): // quay.io/abc123
		registry = &Quay{}
	case strings.HasPrefix(namespace, "ghcr.io"): // ghcr.io/abc123
		registry = &GHCR{}
	default: // default is dockerhub
		registry = &DockerHub{}
	}

	return registry
}

// === DockerHub registry ===

// DockerHub implements the Registry interface for Docker Hub.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://hub.docker.com/v2/namespaces/%s/repositories", namespace), http.NoBody)
	if err != nil {
		return nil, err
	}

	if d.Token != "" {
		req.Header.Set("Authorization", "Bearer "+d.Token)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var allImages = make([]string, 0)

		var listImagesResp dockerhubResp
		if err := json.Unmarshal(responseBodyByte, &listImagesResp); err != nil {
			return nil, err
		}

		for _, image := range listImagesResp.Results {
			allImages = append(allImages, fmt.Sprintf("%s/%s", namespace, image.Name)) // <namespace>/<image_name>
		}

		return allImages, nil
	default:
		return nil, fmt.Errorf("failed to list dockerhub images: unexpected status code: %d", resp.StatusCode)
	}
}

// === Red Hat Quay Registry ===

// Quay implements the Registry interface for Quay.io.
type Quay struct {
	Token string
}

// quayResp models the JSON structure returned by Quay's /api/v1/repository endpoint.
type quayResp struct {
	Repositories []Image `json:"repositories"`
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://quay.io/api/v1/repository?namespace=%s&public=true&private=true", quayNamespace), http.NoBody)
	if err != nil {
		return nil, err
	}

	if q.Token != "" {
		req.Header.Set("Authorization", "Bearer "+q.Token)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var allImages = make([]string, 0)

		var listImagesResp quayResp
		if err := json.Unmarshal(responseBodyByte, &listImagesResp); err != nil {
			return nil, err
		}

		for _, image := range listImagesResp.Repositories {
			allImages = append(allImages, fmt.Sprintf("%s/%s", namespace, image.Name)) // quay.io/<namespace>/<image_name>
		}

		return allImages, nil
	default:
		return nil, fmt.Errorf("failed to list quay images: unexpected status code: %d", resp.StatusCode)
	}
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

// ListImages lists all images under a Quay namespace.
func (g *GHCR) ListImages(ctx context.Context, namespace string) ([]string, error) {
	ghcrNamespace := path.Base(namespace) // ghcr.io/<namespace> -> namespace

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://api.github.com/users/%s/packages?package_type=container", ghcrNamespace), http.NoBody)
	if err != nil {
		return nil, err
	}

	// https://stackoverflow.com/questions/72732582/using-github-packages-without-personal-access-token
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var allImages = make([]string, 0)

		var listImagesResp []Image
		if err := json.Unmarshal(responseBodyByte, &listImagesResp); err != nil {
			return nil, err
		}

		for _, image := range listImagesResp {
			allImages = append(allImages, fmt.Sprintf("%s/%s", namespace, image.Name)) // ghcr.io/<namespace>/<image_name>
		}

		return allImages, nil
	default:
		return nil, fmt.Errorf("failed to list ghcr images: unexpected status code: %d", resp.StatusCode)
	}
}
