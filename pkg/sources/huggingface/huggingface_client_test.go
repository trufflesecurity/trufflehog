package huggingface

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

const (
	TEST_TOKEN = "test token"
)

func initTestClient() *HFClient {
	return NewHFClient("https://huggingface.co", TEST_TOKEN, 10*time.Second)
}

func TestGetRepo(t *testing.T) {
	resourceType := MODEL
	repoName := "test-model"
	repoOwner := "test-author"
	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(resourceType)+"/"+repoName).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(200).
		JSON(map[string]interface{}{
			"id":      repoOwner + "/" + repoName,
			"author":  repoOwner,
			"private": true,
		})

	client := initTestClient()
	model, err := client.GetRepo(context.Background(), repoName, resourceType)

	assert.Nil(t, err)
	assert.NotNil(t, model)
	assert.Equal(t, repoOwner+"/"+repoName, model.RepoID)
	assert.Equal(t, repoOwner, model.Owner)
	assert.Equal(t, true, model.IsPrivate)
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestGetRepo_NotFound(t *testing.T) {
	resourceType := MODEL
	repoName := "doesnotexist"
	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(resourceType)+"/"+repoName).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(404).
		JSON(map[string]interface{}{
			"id":      "",
			"author":  "",
			"private": false,
		})

	client := initTestClient()
	model, err := client.GetRepo(context.Background(), repoName, resourceType)

	assert.Nil(t, err)
	assert.NotNil(t, model)
	assert.Equal(t, "", model.RepoID)
	assert.Equal(t, "", model.Owner)
	assert.Equal(t, false, model.IsPrivate)
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestGetModel_Error(t *testing.T) {
	resourceType := MODEL
	repoName := "doesnotexist"
	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(resourceType)+"/"+repoName).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(500)

	client := initTestClient()
	model, err := client.GetRepo(context.Background(), repoName, resourceType)

	assert.NotNil(t, err)
	assert.NotNil(t, model)
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestListDiscussions(t *testing.T) {
	repoInfo := repoInfo{
		fullName:     "test-author/test-model",
		resourceType: MODEL,
	}

	jsonBlob := `{
		"discussions": [
			{
				"num": 2,
				"author": {
					"avatarUrl": "/avatars/test.svg",
					"fullname": "TEST",
					"name": "test-author",
					"type": "user",
					"isPro": false,
					"isHf": false,
					"isMod": false
				},
				"repo": {
					"name": "test-author/test-model",
					"type": "model"
				},
				"title": "new PR",
				"status": "open",
				"createdAt": "2024-06-18T14:34:21.000Z",
				"isPullRequest": true,
				"numComments": 2,
				"pinned": false
			},
			{
				"num": 1,
				"author": {
					"avatarUrl": "/avatars/test.svg",
					"fullname": "TEST",
					"name": "test-author",
					"type": "user",
					"isPro": false,
					"isHf": false,
					"isMod": false
				},
				"repo": {
					"name": "test-author/test-model",
					"type": "model"
				},
				"title": "secret in comment",
				"status": "closed",
				"createdAt": "2024-06-18T14:31:57.000Z",
				"isPullRequest": false,
				"numComments": 2,
				"pinned": false
			}
		],
		"count": 2,
		"start": 0,
		"numClosedDiscussions": 1
	}`

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(string(repoInfo.resourceType))+"/"+repoInfo.fullName+"/"+DiscussionsRoute).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(200).
		JSON(jsonBlob)

	client := initTestClient()
	discussions, err := client.ListDiscussions(context.Background(), repoInfo)

	assert.Nil(t, err)
	assert.NotNil(t, discussions)
	assert.Equal(t, 2, len(discussions.Discussions))
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestListDiscussions_NotFound(t *testing.T) {
	repoInfo := repoInfo{
		fullName:     "test-author/doesnotexist",
		resourceType: MODEL,
	}
	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(string(repoInfo.resourceType))+"/"+repoInfo.fullName+"/"+DiscussionsRoute).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(404).
		JSON(map[string]interface{}{
			"discussions": []map[string]interface{}{},
		})

	client := initTestClient()
	discussions, err := client.ListDiscussions(context.Background(), repoInfo)

	assert.Nil(t, err)
	assert.NotNil(t, discussions)
	assert.Equal(t, 0, len(discussions.Discussions))
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestListDiscussions_Error(t *testing.T) {
	repoInfo := repoInfo{
		fullName:     "test-author/doesnotexist",
		resourceType: MODEL,
	}
	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(string(repoInfo.resourceType))+"/"+repoInfo.fullName+"/"+DiscussionsRoute).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(500)

	client := initTestClient()
	discussions, err := client.ListDiscussions(context.Background(), repoInfo)

	assert.NotNil(t, err)
	assert.NotNil(t, discussions)
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestGetDiscussionByID(t *testing.T) {
	repoInfo := repoInfo{
		fullName:     "test-author/test-model",
		resourceType: MODEL,
	}
	discussionID := "1"

	jsonBlob := `{
		"author": {
			"avatarUrl": "/avatars/test.svg",
			"fullname": "TEST",
			"name": "test-author",
			"type": "user",
			"isPro": false,
			"isHf": false,
			"isMod": false
		},
		"num": 1,
		"repo": {
			"name": "test-author/test-model",
			"type": "model"
		},
		"title": "secret in initial",
		"status": "open",
		"createdAt": "2024-06-18T14:31:46.000Z",
		"events": [
			{
				"id": "525",
				"author": {
					"avatarUrl": "/avatars/test.svg",
					"fullname": "TEST",
					"name": "test-author",
					"type": "user",
					"isPro": false,
					"isHf": false,
					"isMod": false,
					"isOwner": true,
					"isOrgMember": false
				},
				"createdAt": "2024-06-18T14:31:46.000Z",
				"type": "comment",
				"data": {
					"edited": true,
					"hidden": false,
					"latest": {
						"raw": "dd",
						"html": "<p>dd</p>\n",
						"updatedAt": "2024-06-18T14:33:32.066Z",
						"author": {
							"avatarUrl": "/avatars/test.svg",
							"fullname": "TEST",
							"name": "test-author",
							"type": "user",
							"isPro": false,
							"isHf": false,
							"isMod": false
						}
					},
					"numEdits": 1,
					"editors": ["trufflej"],
					"reactions": [],
					"identifiedLanguage": {
						"language": "en",
						"probability": 0.40104949474334717
					},
					"isReport": false
				}
			},
			{
				"id": "526",
				"author": {
					"avatarUrl": "/avatars/test.svg",
					"fullname": "TEST",
					"name": "test-author",
					"type": "user",
					"isPro": false,
					"isHf": false,
					"isMod": false,
					"isOwner": true,
					"isOrgMember": false
				},
				"createdAt": "2024-06-18T14:32:40.000Z",
				"type": "status-change",
				"data": {
					"status": "closed"
				}
			},
			{
				"id": "527",
				"author": {
					"avatarUrl": "/avatars/test.svg",
					"fullname": "TEST",
					"name": "test-author",
					"type": "user",
					"isPro": false,
					"isHf": false,
					"isMod": false,
					"isOwner": true,
					"isOrgMember": false
				},
				"createdAt": "2024-06-18T14:33:27.000Z",
				"type": "status-change",
				"data": {
					"status": "open"
				}
			}
		],
		"pinned": false,
		"locked": false,
		"isPullRequest": false,
		"isReport": false
	}`

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(string(repoInfo.resourceType))+"/"+repoInfo.fullName+"/"+DiscussionsRoute+"/"+discussionID).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(200).
		JSON(jsonBlob)

	client := initTestClient()
	discussion, err := client.GetDiscussionByID(context.Background(), repoInfo, discussionID)

	assert.Nil(t, err)
	assert.NotNil(t, discussion)
	assert.Equal(t, discussionID, strconv.Itoa(discussion.ID))
	assert.Equal(t, 3, len(discussion.Events))
	assert.Equal(t, false, discussion.IsPR)
	assert.Equal(t, "secret in initial", discussion.Title)
	assert.Equal(t, repoInfo.fullName, discussion.Repo.FullName)
	assert.Equal(t, string(repoInfo.resourceType), discussion.Repo.ResourceType)
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestGetDiscussionByID_NotFound(t *testing.T) {
	repoInfo := repoInfo{
		fullName:     "test-author/test-model",
		resourceType: MODEL,
	}
	discussionID := "doesnotexist"
	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(string(repoInfo.resourceType))+"/"+repoInfo.fullName+"/"+DiscussionsRoute+"/"+discussionID).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(404).
		JSON(map[string]interface{}{})

	client := initTestClient()
	discussion, err := client.GetDiscussionByID(context.Background(), repoInfo, discussionID)

	assert.Nil(t, err)
	assert.NotNil(t, discussion)
	assert.Equal(t, 0, len(discussion.Events))
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestGetDiscussionByID_Error(t *testing.T) {
	repoInfo := repoInfo{
		fullName:     "test-author/test-model",
		resourceType: MODEL,
	}
	discussionID := "doesnotexist"
	defer gock.Off()

	gock.New("https://huggingface.co").
		Get("/"+APIRoute+"/"+getResourceAPIPath(string(repoInfo.resourceType))+"/"+repoInfo.fullName+"/"+DiscussionsRoute+"/"+discussionID).
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(500)

	client := initTestClient()
	discussion, err := client.GetDiscussionByID(context.Background(), repoInfo, discussionID)

	assert.NotNil(t, err)
	assert.NotNil(t, discussion)
	assert.Equal(t, "", discussion.Title)
	assert.Equal(t, 0, len(discussion.Events))
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestListReposByAuthor(t *testing.T) {
	resourceType := MODEL
	author := "test-author"
	repo := "test-model"
	repo2 := "test-model2"

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(resourceType))).
		MatchParam("author", author).
		MatchParam("limit", "1000").
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "1",
				"id":      author + "/" + repo,
				"modelId": author + "/" + repo,
				"private": true,
			},
			{
				"_id":     "2",
				"id":      author + "/" + repo2,
				"modelId": author + "/" + repo2,
				"private": false,
			},
		})

	for _, mock := range gock.Pending() {
		fmt.Println(mock.Request().URLStruct.String())
	}

	client := initTestClient()
	repos, err := client.ListReposByAuthor(context.Background(), resourceType, author)
	assert.Nil(t, err)
	assert.NotNil(t, repos)
	assert.Equal(t, 2, len(repos))
	// count of repos with private flag
	countOfPrivateRepos := 0
	for _, repo := range repos {
		if repo.IsPrivate {
			countOfPrivateRepos++
		}
	}
	assert.Equal(t, 1, countOfPrivateRepos)
	// there is no author field in JSON, so assert repo.Owner is empty
	for _, repo := range repos {
		assert.Equal(t, "", repo.Owner)
	}
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestListReposByAuthor_NotFound(t *testing.T) {
	resourceType := MODEL
	author := "authordoesntexist"

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(resourceType))).
		MatchParam("author", author).
		MatchParam("limit", "1000").
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(404).
		JSON([]map[string]interface{}{})

	client := initTestClient()
	repos, err := client.ListReposByAuthor(context.Background(), resourceType, author)

	assert.Nil(t, err)
	assert.NotNil(t, repos)
	assert.Equal(t, 0, len(repos))
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestListReposByAuthor_Error(t *testing.T) {
	resourceType := MODEL
	author := "doesnotexist"

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(resourceType))).
		MatchParam("author", author).
		MatchParam("limit", "1000").
		MatchHeader("Authorization", "Bearer "+TEST_TOKEN).
		Reply(500)

	client := initTestClient()
	repos, err := client.ListReposByAuthor(context.Background(), resourceType, author)
	assert.NotNil(t, err)
	assert.Nil(t, repos)
	assert.False(t, gock.HasUnmatchedRequest())
	assert.True(t, gock.IsDone())
}

func TestGetResourceAPIPath(t *testing.T) {
	assert.Equal(t, "models", getResourceAPIPath(MODEL))
	assert.Equal(t, "datasets", getResourceAPIPath(DATASET))
	assert.Equal(t, "spaces", getResourceAPIPath(SPACE))
}

func TestGetResourceHTMLPath(t *testing.T) {
	assert.Equal(t, "", getResourceHTMLPath(MODEL))
	assert.Equal(t, "datasets", getResourceHTMLPath(DATASET))
	assert.Equal(t, "spaces", getResourceHTMLPath(SPACE))
}

func TestBuildAPIURL_ValidInputs(t *testing.T) {
	endpoint := "https://huggingface.co"
	resourceType := MODEL
	repoName := "test-repo"

	expectedURL := "https://huggingface.co/api/models/test-repo"

	url, err := buildAPIURL(endpoint, resourceType, repoName)

	assert.Nil(t, err)
	assert.Equal(t, expectedURL, url)
}

func TestBuildAPIURL_EmptyEndpoint(t *testing.T) {
	endpoint := ""
	resourceType := MODEL
	repoName := "test-repo"

	url, err := buildAPIURL(endpoint, resourceType, repoName)

	assert.NotNil(t, err)
	assert.Equal(t, "", url)
	assert.Equal(t, "endpoint, resourceType, and repoName must not be empty", err.Error())
}

func TestBuildAPIURL_EmptyResourceType(t *testing.T) {
	endpoint := "https://huggingface.co"
	resourceType := ""
	repoName := "test-repo"

	url, err := buildAPIURL(endpoint, resourceType, repoName)

	assert.NotNil(t, err)
	assert.Equal(t, "", url)
	assert.Equal(t, "endpoint, resourceType, and repoName must not be empty", err.Error())
}

func TestBuildAPIURL_EmptyRepoName(t *testing.T) {
	endpoint := "https://huggingface.co"
	resourceType := "model"
	repoName := ""

	url, err := buildAPIURL(endpoint, resourceType, repoName)

	assert.NotNil(t, err)
	assert.Equal(t, "", url)
	assert.Equal(t, "endpoint, resourceType, and repoName must not be empty", err.Error())
}

func TestGetDiscussionPath_ModelResource(t *testing.T) {
	discussion := Discussion{
		Repo: RepoData{
			FullName:     "test-author/test-model",
			ResourceType: "model",
		},
		ID: 1,
	}

	expectedPath := "test-author/test-model/discussions/1"

	path := discussion.GetDiscussionPath()
	assert.Equal(t, expectedPath, path)
}

func TestGetDiscussionPath_DatasetResource(t *testing.T) {
	discussion := Discussion{
		Repo: RepoData{
			FullName:     "test-author/test-dataset",
			ResourceType: "dataset",
		},
		ID: 1,
	}

	expectedPath := "datasets/test-author/test-dataset/discussions/1"

	path := discussion.GetDiscussionPath()
	assert.Equal(t, expectedPath, path)
}

func TestGetDiscussionPath_SpaceResource(t *testing.T) {
	discussion := Discussion{
		Repo: RepoData{
			FullName:     "test-author/test-space",
			ResourceType: "space",
		},
		ID: 1,
	}

	expectedPath := "spaces/test-author/test-space/discussions/1"

	path := discussion.GetDiscussionPath()
	assert.Equal(t, expectedPath, path)
}

func TestGetGitPath_ModelResource(t *testing.T) {
	discussion := Discussion{
		Repo: RepoData{
			FullName:     "test-author/test-model",
			ResourceType: "model",
		},
		ID: 1,
	}

	expectedPath := "test-author/test-model.git"

	path := discussion.GetGitPath()
	assert.Equal(t, expectedPath, path)
}

func TestGetGitPath_DatasetResource(t *testing.T) {
	discussion := Discussion{
		Repo: RepoData{
			FullName:     "test-author/test-dataset",
			ResourceType: "dataset",
		},
		ID: 1,
	}

	expectedPath := "datasets/test-author/test-dataset.git"

	path := discussion.GetGitPath()
	assert.Equal(t, expectedPath, path)
}

func TestGetGitPath_SpaceResource(t *testing.T) {
	discussion := Discussion{
		Repo: RepoData{
			FullName:     "test-author/test-space",
			ResourceType: "space",
		},
		ID: 1,
	}

	expectedPath := "spaces/test-author/test-space.git"

	path := discussion.GetGitPath()
	assert.Equal(t, expectedPath, path)
}
