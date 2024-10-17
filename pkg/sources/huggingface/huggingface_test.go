package huggingface

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/h2non/gock.v1"
)

func createTestSource(src *sourcespb.Huggingface) (*Source, *anypb.Any) {
	s := &Source{}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}
	return s, conn
}

// test include exclude ignore/include orgs, users

func TestInit(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Models:         []string{"user/model1", "user/model2", "user/ignorethismodel"},
		IgnoreModels:   []string{"user/ignorethismodel"},
		Spaces:         []string{"user/space1", "user/space2", "user/ignorethisspace"},
		IgnoreSpaces:   []string{"user/ignorethisspace"},
		Datasets:       []string{"user/dataset1", "user/dataset2", "user/ignorethisdataset"},
		IgnoreDatasets: []string{"user/ignorethisdataset"},
		Organizations:  []string{"org1", "org2"},
		Users:          []string{"user1", "user2"},
	})
	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	assert.ElementsMatch(t, []string{"user/model1", "user/model2"}, s.models)
	for _, model := range s.models {
		modelURL, _ := s.filteredModelsCache.Get(model)
		assert.Equal(t, modelURL, s.conn.Endpoint+"/"+model+".git")
	}

	assert.ElementsMatch(t, []string{"user/space1", "user/space2"}, s.spaces)
	for _, space := range s.spaces {
		spaceURL, _ := s.filteredSpacesCache.Get(space)
		assert.Equal(t, spaceURL, s.conn.Endpoint+"/"+getResourceHTMLPath(SPACE)+"/"+space+".git")
	}

	assert.ElementsMatch(t, []string{"user/dataset1", "user/dataset2"}, s.datasets)
	for _, dataset := range s.datasets {
		datasetURL, _ := s.filteredDatasetsCache.Get(dataset)
		assert.Equal(t, datasetURL, s.conn.Endpoint+"/"+getResourceHTMLPath(DATASET)+"/"+dataset+".git")
	}

	assert.ElementsMatch(t, s.conn.Organizations, s.orgsCache.Keys())
	assert.ElementsMatch(t, s.conn.Users, s.usersCache.Keys())
}

func TestGetResourceType(t *testing.T) {
	repo := "author/model1"
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Models: []string{repo},
	})
	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	// mock the request to the huggingface api
	gock.New("https://huggingface.co").
		Get("/api/models/author/model1").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "author/model1",
			"author":  "author",
			"private": true,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, MODEL, s.getResourceType(context.Background(), (s.conn.Endpoint+"/"+repo+".git")))
}

func TestVisibilityOf(t *testing.T) {
	repo := "author/model1"
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Models: []string{repo},
	})
	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	// mock the request to the huggingface api
	gock.New("https://huggingface.co").
		Get("/api/models/author/model1").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "author/model1",
			"author":  "author",
			"private": true,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, source_metadatapb.Visibility(1), s.visibilityOf(context.Background(), (s.conn.Endpoint+"/"+repo+".git")))
}

func TestEnumerate(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Models:   []string{"author/model1"},
		Datasets: []string{"author/dataset1"},
		Spaces:   []string{"author/space1"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	// mock the request to the huggingface api
	gock.New("https://huggingface.co").
		Get("/api/models/author/model1").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "author/model1",
			"author":  "author",
			"private": true,
		})

	gock.New("https://huggingface.co").
		Get("/api/datasets/author/dataset1").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "author/dataset1",
			"author":  "author",
			"private": false,
		})

	gock.New("https://huggingface.co").
		Get("/api/spaces/author/space1").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "author/space1",
			"author":  "author",
			"private": false,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/author/model1.git"
	datasetGitURL := "https://huggingface.co/datasets/author/dataset1.git"
	spaceGitURL := "https://huggingface.co/spaces/author/space1.git"

	assert.Equal(t, []string{modelGitURL}, s.models)
	assert.Equal(t, []string{datasetGitURL}, s.datasets)
	assert.Equal(t, []string{spaceGitURL}, s.spaces)

	r, _ := s.repoInfoCache.get(modelGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_private,
		resourceType: MODEL,
		owner:        "author",
		name:         "model1",
		fullName:     "author/model1",
	})

	r, _ = s.repoInfoCache.get(datasetGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_public,
		resourceType: DATASET,
		owner:        "author",
		name:         "dataset1",
		fullName:     "author/dataset1",
	})

	r, _ = s.repoInfoCache.get(spaceGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_public,
		resourceType: SPACE,
		owner:        "author",
		name:         "space1",
		fullName:     "author/space1",
	})

}

func TestUpdateRepoList(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/author/model1.git"
	datasetGitURL := "https://huggingface.co/datasets/author/dataset1.git"
	spaceGitURL := "https://huggingface.co/spaces/author/space1.git"

	s.updateRepoLists(modelGitURL, MODEL)
	s.updateRepoLists(datasetGitURL, DATASET)
	s.updateRepoLists(spaceGitURL, SPACE)

	assert.Equal(t, []string{modelGitURL}, s.models)
	assert.Equal(t, []string{datasetGitURL}, s.datasets)
	assert.Equal(t, []string{spaceGitURL}, s.spaces)
}

func TestGetReposListByType(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Models:   []string{"author/model1", "author/model2"},
		Datasets: []string{"author/dataset1", "author/dataset2"},
		Spaces:   []string{"author/space1", "author/space2"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	assert.Equal(t, s.getReposListByType(MODEL), s.models)
	assert.Equal(t, s.getReposListByType(DATASET), s.datasets)
	assert.Equal(t, s.getReposListByType(SPACE), s.spaces)
}

func TestGetVisibility(t *testing.T) {
	assert.Equal(t, source_metadatapb.Visibility(1), getVisibility(true))
	assert.Equal(t, source_metadatapb.Visibility(0), getVisibility(false))
}

func TestEnumerateAuthorsOrg(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Organizations: []string{"org"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	// mock the request to the huggingface api
	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(MODEL))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "1",
				"id":      "org/model",
				"modelId": "org/model",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/models/org/model").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/model",
			"author":  "org",
			"private": true,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(DATASET))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "3",
				"id":      "org/dataset",
				"modelId": "org/dataset",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/datasets/org/dataset").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/dataset",
			"author":  "org",
			"private": true,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(SPACE))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "5",
				"id":      "org/space",
				"modelId": "org/space",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/spaces/org/space").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/space",
			"author":  "org",
			"private": true,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/org/model.git"
	datasetGitURL := "https://huggingface.co/datasets/org/dataset.git"
	spaceGitURL := "https://huggingface.co/spaces/org/space.git"

	assert.Equal(t, []string{modelGitURL}, s.models)
	assert.Equal(t, []string{datasetGitURL}, s.datasets)
	assert.Equal(t, []string{spaceGitURL}, s.spaces)

	r, _ := s.repoInfoCache.get(modelGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_private,
		resourceType: MODEL,
		owner:        "org",
		name:         "model",
		fullName:     "org/model",
	})

	r, _ = s.repoInfoCache.get(datasetGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_private,
		resourceType: DATASET,
		owner:        "org",
		name:         "dataset",
		fullName:     "org/dataset",
	})

	r, _ = s.repoInfoCache.get(spaceGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_private,
		resourceType: SPACE,
		owner:        "org",
		name:         "space",
		fullName:     "org/space",
	})
}

func TestEnumerateAuthorsOrgSkipAll(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Organizations:   []string{"org"},
		SkipAllModels:   true,
		SkipAllDatasets: true,
		SkipAllSpaces:   true,
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	// mock the request to the huggingface api
	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(MODEL))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "1",
				"id":      "org/model",
				"modelId": "org/model",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/models/org/model").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/model",
			"author":  "org",
			"private": true,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(DATASET))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "3",
				"id":      "org/dataset",
				"modelId": "org/dataset",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/datasets/org/dataset").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/dataset",
			"author":  "org",
			"private": true,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(SPACE))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "5",
				"id":      "org/space",
				"modelId": "org/space",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/spaces/org/space").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/space",
			"author":  "org",
			"private": true,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/org/model.git"
	datasetGitURL := "https://huggingface.co/datasets/org/dataset.git"
	spaceGitURL := "https://huggingface.co/spaces/org/space.git"

	assert.Equal(t, []string{}, s.models)
	assert.Equal(t, []string{}, s.datasets)
	assert.Equal(t, []string{}, s.spaces)

	r, _ := s.repoInfoCache.get(modelGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(datasetGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(spaceGitURL)
	assert.Equal(t, r, repoInfo{})
}

func TestEnumerateAuthorsOrgIgnores(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Organizations:  []string{"org"},
		IgnoreModels:   []string{"org/model"},
		IgnoreDatasets: []string{"org/dataset"},
		IgnoreSpaces:   []string{"org/space"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	// mock the request to the huggingface api
	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(MODEL))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "1",
				"id":      "org/model",
				"modelId": "org/model",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/models/org/model").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/model",
			"author":  "org",
			"private": true,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(DATASET))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "3",
				"id":      "org/dataset",
				"modelId": "org/dataset",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/datasets/org/dataset").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/dataset",
			"author":  "org",
			"private": true,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(SPACE))).
		MatchParam("author", "org").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "5",
				"id":      "org/space",
				"modelId": "org/space",
				"private": true,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/spaces/org/space").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "org/space",
			"author":  "org",
			"private": true,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/org/model.git"
	datasetGitURL := "https://huggingface.co/datasets/org/dataset.git"
	spaceGitURL := "https://huggingface.co/spaces/org/space.git"

	assert.Equal(t, []string{}, s.models)
	assert.Equal(t, []string{}, s.datasets)
	assert.Equal(t, []string{}, s.spaces)

	r, _ := s.repoInfoCache.get(modelGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(datasetGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(spaceGitURL)
	assert.Equal(t, r, repoInfo{})
}

func TestEnumerateAuthorsUser(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Users: []string{"user"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(MODEL))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "2",
				"id":      "user/model",
				"modelId": "user/model",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/models/user/model").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/model",
			"author":  "user",
			"private": false,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(DATASET))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "4",
				"id":      "user/dataset",
				"modelId": "user/dataset",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/datasets/user/dataset").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/dataset",
			"author":  "user",
			"private": false,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(SPACE))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "6",
				"id":      "user/space",
				"modelId": "user/space",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/spaces/user/space").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/space",
			"author":  "user",
			"private": false,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/user/model.git"
	datasetGitURL := "https://huggingface.co/datasets/user/dataset.git"
	spaceGitURL := "https://huggingface.co/spaces/user/space.git"

	assert.Equal(t, []string{modelGitURL}, s.models)
	assert.Equal(t, []string{datasetGitURL}, s.datasets)
	assert.Equal(t, []string{spaceGitURL}, s.spaces)

	r, _ := s.repoInfoCache.get(modelGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_public,
		resourceType: MODEL,
		owner:        "user",
		name:         "model",
		fullName:     "user/model",
	})

	r, _ = s.repoInfoCache.get(datasetGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_public,
		resourceType: DATASET,
		owner:        "user",
		name:         "dataset",
		fullName:     "user/dataset",
	})

	r, _ = s.repoInfoCache.get(spaceGitURL)
	assert.Equal(t, r, repoInfo{
		visibility:   source_metadatapb.Visibility_public,
		resourceType: SPACE,
		owner:        "user",
		name:         "space",
		fullName:     "user/space",
	})
}

func TestEnumerateAuthorsUserSkipAll(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Users:           []string{"user"},
		SkipAllModels:   true,
		SkipAllDatasets: true,
		SkipAllSpaces:   true,
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(MODEL))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "2",
				"id":      "user/model",
				"modelId": "user/model",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/models/user/model").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/model",
			"author":  "user",
			"private": false,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(DATASET))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "4",
				"id":      "user/dataset",
				"modelId": "user/dataset",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/datasets/user/dataset").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/dataset",
			"author":  "user",
			"private": false,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(SPACE))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "6",
				"id":      "user/space",
				"modelId": "user/space",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/spaces/user/space").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/space",
			"author":  "user",
			"private": false,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/user/model.git"
	datasetGitURL := "https://huggingface.co/datasets/user/dataset.git"
	spaceGitURL := "https://huggingface.co/spaces/user/space.git"

	assert.Equal(t, []string{}, s.models)
	assert.Equal(t, []string{}, s.datasets)
	assert.Equal(t, []string{}, s.spaces)

	r, _ := s.repoInfoCache.get(modelGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(datasetGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(spaceGitURL)
	assert.Equal(t, r, repoInfo{})
}

func TestEnumerateAuthorsUserIgnores(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Users:          []string{"user"},
		IgnoreModels:   []string{"user/model"},
		IgnoreDatasets: []string{"user/dataset"},
		IgnoreSpaces:   []string{"user/space"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	defer gock.Off()

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(MODEL))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "2",
				"id":      "user/model",
				"modelId": "user/model",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/models/user/model").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/model",
			"author":  "user",
			"private": false,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(DATASET))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "4",
				"id":      "user/dataset",
				"modelId": "user/dataset",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/datasets/user/dataset").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/dataset",
			"author":  "user",
			"private": false,
		})

	gock.New("https://huggingface.co").
		Get(fmt.Sprintf("/%s/%s", APIRoute, getResourceAPIPath(SPACE))).
		MatchParam("author", "user").
		MatchParam("limit", "1000").
		Reply(200).
		JSON([]map[string]interface{}{
			{
				"_id":     "6",
				"id":      "user/space",
				"modelId": "user/space",
				"private": false,
			},
		})

	gock.New("https://huggingface.co").
		Get("/api/spaces/user/space").
		Reply(200).
		JSON(map[string]interface{}{
			"id":      "user/space",
			"author":  "user",
			"private": false,
		})

	err = s.enumerate(context.Background())
	assert.Nil(t, err)

	modelGitURL := "https://huggingface.co/user/model.git"
	datasetGitURL := "https://huggingface.co/datasets/user/dataset.git"
	spaceGitURL := "https://huggingface.co/spaces/user/space.git"

	assert.Equal(t, []string{}, s.models)
	assert.Equal(t, []string{}, s.datasets)
	assert.Equal(t, []string{}, s.spaces)

	r, _ := s.repoInfoCache.get(modelGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(datasetGitURL)
	assert.Equal(t, r, repoInfo{})

	r, _ = s.repoInfoCache.get(spaceGitURL)
	assert.Equal(t, r, repoInfo{})
}

func TestVerifySlashSeparatedStrings(t *testing.T) {
	assert.Error(t, verifySlashSeparatedStrings([]string{"orgmodel"}))
	assert.NoError(t, verifySlashSeparatedStrings([]string{"org/model"}))
	assert.Error(t, verifySlashSeparatedStrings([]string{"org/model", "orgmodel2"}))
	assert.NoError(t, verifySlashSeparatedStrings([]string{"org/model", "org/model2"}))
}

func TestValidateIgnoreIncludeReposRepos(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Organizations:  []string{"org"},
		IgnoreModels:   []string{"orgmodel1"},
		IgnoreDatasets: []string{"org/dataset1"},
		IgnoreSpaces:   []string{"org/space1"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.NotNil(t, err)
}

func TestValidateIgnoreIncludeReposDatasets(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Organizations:  []string{"org"},
		IgnoreModels:   []string{"org/model1"},
		IgnoreDatasets: []string{"orgdataset1"},
		IgnoreSpaces:   []string{"org/space1"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.NotNil(t, err)
}

func TestValidateIgnoreIncludeReposSpaces(t *testing.T) {
	s, conn := createTestSource(&sourcespb.Huggingface{
		Endpoint: "https://huggingface.co",
		Credential: &sourcespb.Huggingface_Token{
			Token: "super secret token",
		},
		Organizations:  []string{"org"},
		IgnoreModels:   []string{"org/model1"},
		IgnoreDatasets: []string{"org/dataset1"},
		IgnoreSpaces:   []string{"orgspace1"},
	})

	err := s.Init(context.Background(), "test - huggingface", 0, 1337, false, conn, 1)
	assert.NotNil(t, err)
}

// repeat this with all skip flags, and then include/ignore flags
