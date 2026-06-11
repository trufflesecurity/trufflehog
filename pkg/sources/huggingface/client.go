package huggingface

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Maps for API and HTML paths
var apiPaths = map[string]string{
	DATASET: DatasetsRoute,
	MODEL:   ModelsAPIRoute,
	SPACE:   SpacesRoute,
	BUCKET:  BucketsRoute,
}

var htmlPaths = map[string]string{
	DATASET: DatasetsRoute,
	MODEL:   "",
	SPACE:   SpacesRoute,
	BUCKET:  BucketsRoute,
}

type Author struct {
	Username string `json:"name"`
}

type Latest struct {
	Raw string `json:"raw"`
}

type Data struct {
	Latest Latest `json:"latest"`
}

type Event struct {
	Type      string `json:"type"`
	Author    Author `json:"author"`
	CreatedAt string `json:"createdAt"`
	Data      Data   `json:"data"`
	ID        string `json:"id"`
}

func (e Event) GetAuthor() string {
	return e.Author.Username
}

func (e Event) GetCreatedAt() string {
	return e.CreatedAt
}

func (e Event) GetID() string {
	return e.ID
}

type RepoData struct {
	FullName     string `json:"name"`
	ResourceType string `json:"type"`
}

type Discussion struct {
	ID        int      `json:"num"`
	IsPR      bool     `json:"isPullRequest"`
	CreatedAt string   `json:"createdAt"`
	Title     string   `json:"title"`
	Events    []Event  `json:"events"`
	Repo      RepoData `json:"repo"`
}

func (d Discussion) GetID() string {
	return fmt.Sprint(d.ID)
}

func (d Discussion) GetTitle() string {
	return d.Title
}

func (d Discussion) GetCreatedAt() string {
	return d.CreatedAt
}

func (d Discussion) GetRepo() string {
	return d.Repo.FullName
}

// GetDiscussionPath returns the path (ex: "/models/user/repo/discussions/1") for the discussion
func (d Discussion) GetDiscussionPath() string {
	basePath := fmt.Sprintf("%s/%s/%s", d.GetRepo(), DiscussionsRoute, d.GetID())
	if d.Repo.ResourceType == "model" {
		return basePath
	}
	return fmt.Sprintf("%s/%s", getResourceHTMLPath(d.Repo.ResourceType), basePath)
}

// GetGitPath returns the path (ex: "/models/user/repo.git") for the repo's git directory
func (d Discussion) GetGitPath() string {
	basePath := fmt.Sprintf("%s.git", d.GetRepo())
	if d.Repo.ResourceType == "model" {
		return basePath
	}
	return fmt.Sprintf("%s/%s", getResourceHTMLPath(d.Repo.ResourceType), basePath)
}

type DiscussionList struct {
	Discussions []Discussion `json:"discussions"`
}

type Repo struct {
	IsPrivate bool   `json:"private"`
	Owner     string `json:"author"`
	RepoID    string `json:"id"`
}

type Bucket struct {
	IsPrivate bool   `json:"private"`
	BucketID  string `json:"id"`
}

type BucketFile struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type HFClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewHFClient creates a new HF client
func NewHFClient(baseURL, apiKey string, timeout time.Duration) *HFClient {
	return &HFClient{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// get makes a GET request to the Hugging Face API
// Note: not addressing rate limit, since it seems very permissive. (ex: "If \
// your account suddenly sends 10k requests then you’re likely to receive 503")
func (c *HFClient) get(ctx context.Context, url string, target interface{}) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HuggingFace API request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request to HuggingFace API: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("invalid API key")
	}

	if resp.StatusCode == http.StatusForbidden {
		return errors.New("access to this repo is restricted and you are not in the authorized list. Visit the repository to ask for access")
	}

	defer func() { _ = resp.Body.Close() }()

	return json.NewDecoder(resp.Body).Decode(target)
}

// GetRepo retrieves repo from the Hugging Face API
func (c *HFClient) GetRepo(ctx context.Context, repoName string, resourceType string) (Repo, error) {
	var repo Repo
	url, err := buildAPIURL(c.BaseURL, resourceType, repoName)
	if err != nil {
		return repo, err
	}
	err = c.get(ctx, url, &repo)
	return repo, err
}

// ListDiscussions retrieves discussions from the Hugging Face API
func (c *HFClient) ListDiscussions(ctx context.Context, repoInfo repoInfo) (DiscussionList, error) {
	var discussions DiscussionList
	baseURL, err := buildAPIURL(c.BaseURL, string(repoInfo.resourceType), repoInfo.fullName)
	if err != nil {
		return discussions, err
	}
	url := fmt.Sprintf("%s/%s", baseURL, DiscussionsRoute)
	err = c.get(ctx, url, &discussions)
	return discussions, err
}

func (c *HFClient) GetDiscussionByID(ctx context.Context, repoInfo repoInfo, discussionID string) (Discussion, error) {
	var discussion Discussion
	baseURL, err := buildAPIURL(c.BaseURL, string(repoInfo.resourceType), repoInfo.fullName)
	if err != nil {
		return discussion, err
	}
	url := fmt.Sprintf("%s/%s/%s", baseURL, DiscussionsRoute, discussionID)
	err = c.get(ctx, url, &discussion)
	return discussion, err
}

// ListReposByAuthor retrieves repos from the Hugging Face API by author (user or org)
// Note: not addressing pagination b/c allow by default 1000 results, which should be enough for 99.99% of cases
func (c *HFClient) ListReposByAuthor(ctx context.Context, resourceType string, author string) ([]Repo, error) {
	var repos []Repo
	url := fmt.Sprintf("%s/%s/%s?limit=1000&author=%s", c.BaseURL, APIRoute, getResourceAPIPath(resourceType), author)
	err := c.get(ctx, url, &repos)
	return repos, err
}

// GetBucket retrieves bucket metadata from the Hugging Face API.
func (c *HFClient) GetBucket(ctx context.Context, bucketID string) (Bucket, error) {
	var bucket Bucket
	url, err := buildAPIURL(c.BaseURL, BUCKET, bucketID)
	if err != nil {
		return bucket, err
	}
	err = c.get(ctx, url, &bucket)
	return bucket, err
}

// ListBucketsByAuthor retrieves buckets from the Hugging Face API by author (user or org).
func (c *HFClient) ListBucketsByAuthor(ctx context.Context, author string) ([]Bucket, error) {
	var buckets []Bucket
	url := fmt.Sprintf("%s/%s/%s/%s?limit=%d", c.BaseURL, APIRoute, BucketsRoute, author, bucketsPagination)
	for url != "" {
		var page []Bucket
		next, err := c.getPage(ctx, url, &page)
		if err != nil {
			return buckets, err
		}
		buckets = append(buckets, page...)
		url = next
	}
	return buckets, nil
}

// ListBucketFiles recursively lists all files in a bucket, following Link
// header pagination.
func (c *HFClient) ListBucketFiles(ctx context.Context, bucketID string) ([]BucketFile, error) {
	var files []BucketFile
	url := fmt.Sprintf("%s/%s/%s/%s/tree?recursive=true&limit=%d", c.BaseURL, APIRoute, BucketsRoute, bucketID, bucketsPagination)
	for url != "" {
		var page []BucketFile
		next, err := c.getPage(ctx, url, &page)
		if err != nil {
			return files, err
		}
		files = append(files, page...)
		url = next
	}
	return files, nil
}

// DownloadBucketFile streams a file's content from a bucket via the resolve
// endpoint. The caller is responsible for closing the returned reader.
func (c *HFClient) DownloadBucketFile(ctx context.Context, bucketID string, path string) (io.ReadCloser, error) {
	// Escape each path segment individually so special characters (spaces,
	// '?', '#', etc.) are encoded while slashes are preserved as separators.
	downloadURL := fmt.Sprintf("%s/%s/%s/resolve/%s", c.BaseURL, BucketsRoute, bucketID, escapePathSegments(path))

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HuggingFace bucket download request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download bucket file %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("failed to download bucket file %s: status %d", path, resp.StatusCode)
	}
	return resp.Body, nil
}

// getPage makes a GET request like get, but additionally returns the "next"
// URL from the response Link header, if any, for paginated endpoints.
func (c *HFClient) getPage(ctx context.Context, url string, target interface{}) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HuggingFace API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request to HuggingFace API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", errors.New("invalid API key")
	}
	if resp.StatusCode == http.StatusForbidden {
		return "", errors.New("access to this resource is restricted and you are not in the authorized list. Visit the resource to ask for access")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from HuggingFace API", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return "", err
	}
	return parseNextLink(resp.Header.Get("Link")), nil
}

// escapePathSegments URL-encodes each slash-separated segment of a path while
// keeping the slashes as separators, e.g. "a b/c?d" -> "a%20b/c%3Fd".
func escapePathSegments(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

// parseNextLink extracts the URL with rel="next" from a Link header value.
// Example: <https://huggingface.co/api/...?cursor=abc>; rel="next"
func parseNextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		sections := strings.Split(part, ";")
		if len(sections) < 2 {
			continue
		}
		urlPart := strings.Trim(strings.TrimSpace(sections[0]), "<>")
		for _, param := range sections[1:] {
			if strings.TrimSpace(param) == `rel="next"` {
				return urlPart
			}
		}
	}
	return ""
}

// getResourceAPIPath returns the API path for the given resource type
func getResourceAPIPath(resourceType string) string {
	return apiPaths[resourceType]
}

// getResourceHTMLPath returns the HTML path for the given resource type
func getResourceHTMLPath(resourceType string) string {
	return htmlPaths[resourceType]
}

func buildAPIURL(endpoint string, resourceType string, repoName string) (string, error) {
	if endpoint == "" || resourceType == "" || repoName == "" {
		return "", errors.New("endpoint, resourceType, and repoName must not be empty")
	}
	return fmt.Sprintf("%s/%s/%s/%s", endpoint, APIRoute, getResourceAPIPath(resourceType), repoName), nil
}
