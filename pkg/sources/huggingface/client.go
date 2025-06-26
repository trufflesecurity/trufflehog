package huggingface

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Maps for API and HTML paths
var apiPaths = map[string]string{
	DATASET: DatasetsRoute,
	MODEL:   ModelsAPIRoute,
	SPACE:   SpacesRoute,
}

var htmlPaths = map[string]string{
	DATASET: DatasetsRoute,
	MODEL:   "",
	SPACE:   SpacesRoute,
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
		return errors.New("invalid API key.")
	}

	if resp.StatusCode == http.StatusForbidden {
		return errors.New("access to this repo is restricted and you are not in the authorized list. Visit the repository to ask for access.")
	}

	defer resp.Body.Close()

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
