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

// GetModels retrieves repos from the Hugging Face API
func GetRepo(ctx context.Context, repoName string, resourceType string, apiKey string, endpoint string) (Repo, error) {
	var repo Repo

	client := http.DefaultClient
	url := buildAPIURL(endpoint, resourceType, repoName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return repo, err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return repo, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&repo)
	if err != nil {
		return repo, err
	}

	return repo, nil
}

// ListDiscussions retrieves discussions from the Hugging Face API
func ListDiscussions(ctx context.Context, apiKey string, endpoint string, repoInfo repoInfo) (Discussions, error) {
	var discussions Discussions

	client := http.DefaultClient

	baseURL := buildAPIURL(endpoint, string(repoInfo.resourceType), repoInfo.fullName)
	url := baseURL + "/" + DiscussionsRoute

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return discussions, err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return discussions, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&discussions)
	if err != nil {
		return discussions, err
	}

	return discussions, nil
}

func GetDiscussionByID(ctx context.Context, apiKey string, endpoint string, repoInfo repoInfo, discussionID string) (Discussion, error) {
	var discussion Discussion

	client := http.DefaultClient

	baseURL := buildAPIURL(endpoint, string(repoInfo.resourceType), repoInfo.fullName)
	url := baseURL + "/" + DiscussionsRoute + "/" + discussionID

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return discussion, err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return discussion, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&discussion)
	if err != nil {
		return discussion, err
	}

	return discussion, nil
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
