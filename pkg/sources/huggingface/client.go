package huggingface

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type Event struct {
	Type   string `json:"type"`
	Author struct {
		Username string `json:"name"`
	} `json:"author"`
	CreatedAt string `json:"createdAt"`
	Data      struct {
		Latest struct {
			Raw string `json:"raw"`
		} `json:"latest"`
	} `json:"data"`
	ID string `json:"id"`
}

func (e Event) GetAuthor() string {
	return e.Author.Username
}

func (e Event) GetCreatedAt() string {
	return e.CreatedAt
}

func (e Event) GetID() string {
	return fmt.Sprint(e.ID)
}

type Discussion struct {
	ID        int     `json:"num"`
	IsPR      bool    `json:"isPullRequest"`
	CreatedAt string  `json:"createdAt"`
	Title     string  `json:"title"`
	Events    []Event `json:"events"`
	Repo      struct {
		FullName     string `json:"name"`
		ResourceType string `json:"type"`
	} `json:"repo"`
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

func (d Discussion) GetDiscussionHTMLPath() string {
	basePath := d.GetRepo() + "/" + DiscussionsRoute + "/" + d.GetID()
	if d.Repo.ResourceType == "model" {
		return basePath
	}
	return getResourceHTMLPath(d.Repo.ResourceType) + "/" + basePath
}

func (d Discussion) GetRepoHTMLPath() string {
	basePath := d.GetRepo() + ".git"
	if d.Repo.ResourceType == "model" {
		return basePath
	}
	return getResourceHTMLPath(d.Repo.ResourceType) + "/" + basePath
}

type Discussions struct {
	Discussions []Discussion `json:"discussions"`
}

type Repo struct {
	IsPrivate bool   `json:"private"`
	Owner     string `json:"author"`
	RepoID    string `json:"id"`
}

// makeHuggingFaceAPIRequest makes a request to the Hugging Face API
func makeHuggingFaceAPIRequest(ctx context.Context, apiKey string, url string, method string, target interface{}) error {
	client := http.DefaultClient

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return json.NewDecoder(resp.Body).Decode(target)
}

// GetModels retrieves repos from the Hugging Face API
func GetRepo(ctx context.Context, repoName string, resourceType string, apiKey string, endpoint string) (Repo, error) {
	var repo Repo
	url := buildAPIURL(endpoint, resourceType, repoName)
	err := makeHuggingFaceAPIRequest(ctx, apiKey, url, "GET", &repo)
	return repo, err
}

// ListDiscussions retrieves discussions from the Hugging Face API
func ListDiscussions(ctx context.Context, apiKey string, endpoint string, repoInfo repoInfo) (Discussions, error) {
	var discussions Discussions
	baseURL := buildAPIURL(endpoint, string(repoInfo.resourceType), repoInfo.fullName)
	url := baseURL + "/" + DiscussionsRoute
	err := makeHuggingFaceAPIRequest(ctx, apiKey, url, "GET", &discussions)
	return discussions, err
}

func GetDiscussionByID(ctx context.Context, apiKey string, endpoint string, repoInfo repoInfo, discussionID string) (Discussion, error) {
	var discussion Discussion
	baseURL := buildAPIURL(endpoint, string(repoInfo.resourceType), repoInfo.fullName)
	url := baseURL + "/" + DiscussionsRoute + "/" + discussionID
	err := makeHuggingFaceAPIRequest(ctx, apiKey, url, "GET", &discussion)
	return discussion, err
}

func GetReposByAuthor(ctx context.Context, apiKey string, endpoint string, resourceType string, author string) ([]Repo, error) {
	var repos []Repo
	url := endpoint + "/" + APIRoute + "/" + getResourceAPIPath(resourceType) + "?limit=1000&author=" + author
	err := makeHuggingFaceAPIRequest(ctx, apiKey, url, "GET", &repos)
	return repos, err
}

func getResourceAPIPath(resourceType string) string {
	switch resourceType {
	case DATASET:
		return DatasetsRoute
	case MODEL:
		return ModelsAPIRoute
	case SPACE:
		return SpacesRoute
	default:
		return ""
	}
}

func getResourceHTMLPath(resourceType string) string {
	switch resourceType {
	case DATASET:
		return DatasetsRoute
	case MODEL:
		return "/"
	case SPACE:
		return SpacesRoute
	default:
		return ""
	}
}

func buildAPIURL(endpoint string, resourceType string, repoName string) string {
	return endpoint + "/" + APIRoute + "/" + getResourceAPIPath(resourceType) + "/" + repoName
}
