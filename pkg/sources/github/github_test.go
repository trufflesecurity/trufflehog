package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v42/github"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/h2non/gock.v1"
)

func createTestSource(src *sourcespb.GitHub) (*Source, *anypb.Any) {
	s := &Source{}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}
	return s, conn
}

func initTestSource(src *sourcespb.GitHub) *Source {
	s, conn := createTestSource(src)
	if err := s.Init(context.TODO(), "test - github", 0, 1337, false, conn, 1); err != nil {
		panic(err)
	}
	gock.InterceptClient(s.httpClient)
	return s
}

func TestInit(t *testing.T) {
	source, conn := createTestSource(&sourcespb.GitHub{
		Repositories: []string{"https://github.com/dustin-decker/secretsandstuff.git"},
		Credential: &sourcespb.GitHub_Token{
			Token: "super secret token",
		},
	})

	err := source.Init(context.TODO(), "test - github", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	// TODO: test error case
}

func TestAddReposByOrg(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	// gock works here because github.NewClient is using the default HTTP Transport
	err := s.addReposByOrg(context.TODO(), github.NewClient(nil), "super-secret-org")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddReposByUser(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	err := s.addReposByUser(context.TODO(), github.NewClient(nil), "super-secret-user")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddGistsByUser(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON([]map[string]string{{"git_pull_url": "super-secret-gist"}})

	s := initTestSource(nil)
	err := s.addGistsByUser(context.TODO(), github.NewClient(nil), "super-secret-user")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-gist"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddMembersByApp(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/app/installations").
		Reply(200).
		JSON([]map[string]interface{}{
			{"account": map[string]string{"login": "super-secret-org"}},
		})
	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/members").
		Reply(200).
		JSON([]map[string]interface{}{
			{"login": "ssm1"},
			{"login": "ssm2"},
			{"login": "ssm3"},
		})

	s := initTestSource(nil)
	err := s.addMembersByApp(context.TODO(), github.NewClient(nil), github.NewClient(nil))
	assert.Nil(t, err)
	assert.Equal(t, 3, len(s.members))
	assert.Equal(t, []string{"ssm1", "ssm2", "ssm3"}, s.members)
	assert.True(t, gock.IsDone())
}

func TestAddReposByApp(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/installation/repositories").
		Reply(200).
		JSON(map[string]interface{}{
			"repositories": []map[string]string{
				{"clone_url": "ssr1"},
				{"clone_url": "ssr2"},
			},
		})

	s := initTestSource(nil)
	err := s.addReposByApp(context.TODO(), github.NewClient(nil))
	assert.Nil(t, err)
	assert.Equal(t, 2, len(s.repos))
	assert.Equal(t, []string{"ssr1", "ssr2"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddOrgsByUser(t *testing.T) {
	defer gock.Off()

	// NOTE: addOrgsByUser calls /user/orgs to get the orgs of the
	// authenticated user
	gock.New("https://api.github.com").
		Get("/user/orgs").
		Reply(200).
		JSON([]map[string]interface{}{
			{"name": "sso1"},
			{"login": "sso2"},
		})

	s := initTestSource(nil)
	s.addOrgsByUser(context.TODO(), github.NewClient(nil), "super-secret-user")
	assert.Equal(t, 2, len(s.orgs))
	assert.Equal(t, []string{"sso1", "sso2"}, s.orgs)
	assert.True(t, gock.IsDone())
}

func TestNormalizeRepos(t *testing.T) {
	defer gock.Off()

	tests := []struct {
		name     string
		setup    func()
		repos    []string
		expected []string
	}{
		{
			name:     "repo url",
			setup:    func() {},
			repos:    []string{"https://github.com/super-secret-user/super-secret-repo"},
			expected: []string{"https://github.com/super-secret-user/super-secret-repo.git"},
		},
		{
			name: "username with gists",
			setup: func() {
				gock.New("https://api.github.com").
					Get("/users/super-secret-user/gists").
					Reply(200).
					JSON([]map[string]string{{"git_pull_url": "https://github.com/super-secret-user/super-secret-gist.git"}})
				gock.New("https://api.github.com").
					Get("/users/super-secret-user/repos").
					Reply(200).
					JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-user/super-secret-repo.git"}})
			},
			repos: []string{"super-secret-user"},
			expected: []string{
				"https://github.com/super-secret-user/super-secret-repo.git",
				"https://github.com/super-secret-user/super-secret-gist.git",
			},
		},
		{
			name: "not found",
			setup: func() {
				gock.New("https://api.github.com").
					Get("/users/not-found/gists").
					Reply(404)
				gock.New("https://api.github.com").
					Get("/users/not-found/repos").
					Reply(404)
			},
			repos:    []string{"not-found"},
			expected: []string{},
		},
		{
			name:     "unexpected format",
			setup:    func() {},
			repos:    []string{"/foo/"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer gock.Off()
			tt.setup()
			s := initTestSource(nil)
			s.repos = tt.repos

			s.normalizeRepos(context.TODO(), github.NewClient(nil))
			assert.Equal(t, len(tt.expected), len(s.repos))
			// sort and compare
			sort.Slice(tt.expected, func(i, j int) bool { return tt.expected[i] < tt.expected[j] })
			sort.Slice(s.repos, func(i, j int) bool { return s.repos[i] < s.repos[j] })
			assert.Equal(t, tt.expected, s.repos)

			assert.True(t, gock.IsDone())
		})
	}
}

func TestHandleRateLimit(t *testing.T) {
	assert.False(t, handleRateLimit(nil, nil))

	err := &github.RateLimitError{}
	res := &github.Response{Response: &http.Response{Header: make(http.Header)}}
	res.Header.Set("x-ratelimit-remaining", "0")
	res.Header.Set("x-ratelimit-reset", strconv.FormatInt(time.Now().Unix()+1, 10))
	assert.True(t, handleRateLimit(err, res))
}

func TestEnumerateUnauthenticated(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	s.orgs = []string{"super-secret-org"}
	_ = s.enumerateUnauthenticated(context.TODO())
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestEnumerateWithToken(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]string{"login": "super-secret-user"})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	_, err := s.enumerateWithToken(context.TODO(), "https://api.github.com", "token")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestEnumerateWithApp(t *testing.T) {
	defer gock.Off()

	// generate a private key (it just needs to be in the right format)
	privateKey := func() string {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		data := x509.MarshalPKCS1PrivateKey(key)
		var pemKey bytes.Buffer
		if err := pem.Encode(&pemKey, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: data,
		}); err != nil {
			panic(err)
		}
		return pemKey.String()
	}()

	gock.New("https://api.github.com").
		Post("/app/installations/1337/access_tokens").
		Reply(200).
		JSON(map[string]string{"token": "dontlook"})

	gock.New("https://api.github.com").
		Get("/installation/repositories").
		Reply(200).
		JSON(map[string]string{})

	s := initTestSource(nil)
	_, _, err := s.enumerateWithApp(
		context.TODO(),
		"https://api.github.com",
		&credentialspb.GitHubApp{
			InstallationId: "1337",
			AppId:          "4141",
			PrivateKey:     privateKey,
		},
	)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(s.repos))

	assert.True(t, gock.IsDone())
}

// This only tests the resume info slice portion of setProgressCompleteWithRepo.
func Test_setProgressCompleteWithRepo(t *testing.T) {
	tests := []struct {
		startingResumeInfoSlice []string
		repoURL                 string
		wantResumeInfoSlice     []string
	}{
		{
			startingResumeInfoSlice: []string{},
			repoURL:                 "a",
			wantResumeInfoSlice:     []string{"a"},
		},
		{
			startingResumeInfoSlice: []string{"b"},
			repoURL:                 "a",
			wantResumeInfoSlice:     []string{"a", "b"},
		},
	}

	logger := logrus.New()
	logger.Out = io.Discard
	s := &Source{
		repos:           []string{},
		log:             logger.WithField("no", "output"),
		resumeInfoMutex: &sync.Mutex{},
	}

	for _, tt := range tests {
		s.resumeInfoSlice = tt.startingResumeInfoSlice
		s.setProgressCompleteWithRepo(0, tt.repoURL)
		if !reflect.DeepEqual(s.resumeInfoSlice, tt.wantResumeInfoSlice) {
			t.Errorf("s.setProgressCompleteWithRepo() got: %v, want: %v", s.resumeInfoSlice, tt.wantResumeInfoSlice)
		}
	}
}

func Test_removeRepoFromResumeInfo(t *testing.T) {
	tests := []struct {
		startingResumeInfoSlice []string
		repoURL                 string
		wantResumeInfoSlice     []string
	}{
		{
			startingResumeInfoSlice: []string{"a", "b", "c"},
			repoURL:                 "a",
			wantResumeInfoSlice:     []string{"b", "c"},
		},
		{
			startingResumeInfoSlice: []string{"a", "b", "c"},
			repoURL:                 "b",
			wantResumeInfoSlice:     []string{"a", "c"},
		},
		{ // This is the probably can't happen case of a repo not in the list.
			startingResumeInfoSlice: []string{"a", "b", "c"},
			repoURL:                 "not in the list",
			wantResumeInfoSlice:     []string{"a", "b", "c"},
		},
	}

	logger := logrus.New()
	logger.Out = io.Discard
	s := &Source{
		repos:           []string{},
		log:             logger.WithField("no", "output"),
		resumeInfoMutex: &sync.Mutex{},
	}

	for _, tt := range tests {
		s.resumeInfoSlice = tt.startingResumeInfoSlice
		s.removeRepoFromResumeInfo(tt.repoURL)
		if !reflect.DeepEqual(s.resumeInfoSlice, tt.wantResumeInfoSlice) {
			t.Errorf("s.removeRepoFromResumeInfo() got: %v, want: %v", s.resumeInfoSlice, tt.wantResumeInfoSlice)
		}
	}
}

func Test_encodeResumeInfo(t *testing.T) {
	tests := []struct {
		startingResumeInfoSlice []string
		wantEncodedResumeInfo   string
	}{
		{
			startingResumeInfoSlice: []string{"a", "b", "c"},
			wantEncodedResumeInfo:   "a\tb\tc",
		},
		{
			startingResumeInfoSlice: []string{},
			wantEncodedResumeInfo:   "",
		},
	}

	logger := logrus.New()
	logger.Out = io.Discard
	s := &Source{
		repos:           []string{},
		log:             logger.WithField("no", "output"),
		resumeInfoMutex: &sync.Mutex{},
	}

	for _, tt := range tests {
		s.resumeInfoSlice = tt.startingResumeInfoSlice
		gotEncodedResumeInfo := s.encodeResumeInfo()
		if gotEncodedResumeInfo != tt.wantEncodedResumeInfo {
			t.Errorf("s.encodeResumeInfo() got: %q, want: %q", gotEncodedResumeInfo, tt.wantEncodedResumeInfo)
		}
	}
}

func Test_decodeResumeInfo(t *testing.T) {
	tests := []struct {
		resumeInfo          string
		wantResumeInfoSlice []string
	}{
		{
			resumeInfo:          "a\tb\tc",
			wantResumeInfoSlice: []string{"a", "b", "c"},
		},
		{
			resumeInfo:          "",
			wantResumeInfoSlice: nil,
		},
	}

	for _, tt := range tests {
		s := &Source{}
		s.decodeResumeInfo(tt.resumeInfo)
		if !reflect.DeepEqual(s.resumeInfoSlice, tt.wantResumeInfoSlice) {
			t.Errorf("s.decodeResumeInfo() got: %v, want: %v", s.resumeInfoSlice, tt.wantResumeInfoSlice)
		}
	}
}

func Test_filterReposToResume(t *testing.T) {
	startingRepos := []string{"a", "b", "c", "d", "e", "f", "g"}

	tests := map[string]struct {
		resumeInfo              string
		wantProgressOffsetCount int
		wantReposToScan         []string
	}{
		"blank resume info": {
			resumeInfo:              "",
			wantProgressOffsetCount: 0,
			wantReposToScan:         startingRepos,
		},
		"starting repos": {
			resumeInfo:              "a\tb",
			wantProgressOffsetCount: 0,
			wantReposToScan:         startingRepos,
		},
		"early contiguous repos": {
			resumeInfo:              "b\tc",
			wantProgressOffsetCount: 1,
			wantReposToScan:         []string{"b", "c", "d", "e", "f", "g"},
		},
		"non-contiguous repos": {
			resumeInfo:              "b\te",
			wantProgressOffsetCount: 3,
			wantReposToScan:         []string{"b", "e", "f", "g"},
		},
		"no repos found in the repo list": {
			resumeInfo:              "not\tthere",
			wantProgressOffsetCount: 0,
			wantReposToScan:         startingRepos,
		},
		"only some repos in the list": {
			resumeInfo:              "c\tnot\tthere",
			wantProgressOffsetCount: 2,
			wantReposToScan:         []string{"c", "d", "e", "f", "g"},
		},
	}

	for name, tt := range tests {
		s := &Source{
			repos:           startingRepos,
			resumeInfoMutex: &sync.Mutex{},
		}

		gotProgressOffsetCount := s.filterReposToResume(tt.resumeInfo)
		if gotProgressOffsetCount != tt.wantProgressOffsetCount {
			t.Errorf("s.filterReposToResume() name: %q got: %d, want: %d", name, gotProgressOffsetCount, tt.wantProgressOffsetCount)
		}
		if !reflect.DeepEqual(s.repos, tt.wantReposToScan) {
			t.Errorf("s.filterReposToResume() name: %q got: %v, want: %v", name, s.repos, tt.wantReposToScan)
		}
	}
}
