package github

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-github/v42/github"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
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
	s.apiClient = github.NewClient(s.httpClient)
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
		JSON([]map[string]string{
			{"clone_url": "super-secret-repo", "name": "super-secret-repo"},
			{"clone_url": "super-secret-repo2", "full_name": "secret/super-secret-repo2"},
		})

	s := initTestSource(nil)
	s.ignoreRepos = []string{"secret/super-*-repo2"}
	// gock works here because github.NewClient is using the default HTTP Transport
	err := s.addRepos(context.TODO(), "super-secret-org", s.getReposByOrg)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddReposByOrg_IncludeRepos(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{
			{"clone_url": "super-secret-repo", "full_name": "secret/super-secret-repo"},
			{"clone_url": "super-secret-repo2", "full_name": "secret/super-secret-repo2"},
			{"clone_url": "super-secret-repo2", "full_name": "secret/not-super-secret-repo"},
		})

	src := &sourcespb.GitHub{
		Organizations: []string{"super-secret-org"},
	}
	s := initTestSource(src)
	s.includeRepos = []string{"secret/super*"}
	// gock works here because github.NewClient is using the default HTTP Transport
	err := s.addRepos(context.TODO(), "super-secret-org", s.getReposByOrg)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo", "super-secret-repo2"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddReposByUser(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{
			{"clone_url": "super-secret-repo", "name": "super-secret-repo"},
			{"clone_url": "super-secret-repo2", "full_name": "secret/super-secret-repo2"},
		})

	s := initTestSource(nil)
	s.ignoreRepos = []string{"secret/super-secret-repo2"}
	err := s.addRepos(context.TODO(), "super-secret-user", s.getReposByUser)
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
	err := s.addGistsByUser(context.TODO(), "super-secret-user")
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
			{"account": map[string]string{"login": "super-secret-org", "type": "Organization"}},
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
	err := s.addMembersByApp(context.TODO(), github.NewClient(nil))
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
	err := s.addReposByApp(context.TODO())
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
			{"login": "sso2"},
		})

	s := initTestSource(nil)
	s.addOrgsByUser(context.TODO(), "super-secret-user")
	assert.Equal(t, 1, len(s.orgs))
	assert.Equal(t, []string{"sso2"}, s.orgs)
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

			s.normalizeRepos(context.TODO())
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
	s := initTestSource(nil)
	assert.False(t, s.handleRateLimit(nil, nil))

	err := &github.RateLimitError{}
	res := &github.Response{Response: &http.Response{Header: make(http.Header)}}
	res.Header.Set("x-ratelimit-remaining", "0")
	res.Header.Set("x-ratelimit-reset", strconv.FormatInt(time.Now().Unix()+1, 10))
	assert.True(t, s.handleRateLimit(err, res))
}

func TestEnumerateUnauthenticated(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	s.orgs = []string{"super-secret-org"}
	s.enumerateUnauthenticated(context.TODO())
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

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON([]map[string]string{{"clone_url": ""}})

	s := initTestSource(nil)
	err := s.enumerateWithToken(context.TODO(), "https://api.github.com", "token")
	assert.Nil(t, err)
	assert.Equal(t, 2, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo", ""}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestEnumerateWithToken_IncludeRepos(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]string{"login": "super-secret-user"})

	s := initTestSource(nil)
	s.repos = []string{"some-special-repo"}

	err := s.enumerateWithToken(context.TODO(), "https://api.github.com", "token")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"some-special-repo"}, s.repos)
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
	_, err := s.enumerateWithApp(
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
func Test_setProgressCompleteWithRepo_resumeInfo(t *testing.T) {
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

	s := &Source{
		repos: []string{},
		log:   logr.Discard(),
	}

	for _, tt := range tests {
		s.resumeInfoSlice = tt.startingResumeInfoSlice
		s.setProgressCompleteWithRepo(0, 0, tt.repoURL)
		if !reflect.DeepEqual(s.resumeInfoSlice, tt.wantResumeInfoSlice) {
			t.Errorf("s.setProgressCompleteWithRepo() got: %v, want: %v", s.resumeInfoSlice, tt.wantResumeInfoSlice)
		}
	}
}

func Test_setProgressCompleteWithRepo_Progress(t *testing.T) {
	repos := []string{"a", "b", "c", "d", "e"}
	tests := map[string]struct {
		repos                 []string
		index                 int
		offset                int
		wantPercentComplete   int64
		wantSectionsCompleted int32
		wantSectionsRemaining int32
	}{
		"starting from the beginning, no offset": {
			repos:                 repos,
			index:                 0,
			offset:                0,
			wantPercentComplete:   0,
			wantSectionsCompleted: 0,
			wantSectionsRemaining: 5,
		},
		"resume from the third, offset 2": {
			repos:                 repos[2:],
			index:                 0,
			offset:                2,
			wantPercentComplete:   40,
			wantSectionsCompleted: 2,
			wantSectionsRemaining: 5,
		},
		"resume from the third, on last repo, offset 2": {
			repos:                 repos[2:],
			index:                 2,
			offset:                2,
			wantPercentComplete:   80,
			wantSectionsCompleted: 4,
			wantSectionsRemaining: 5,
		},
	}

	for _, tt := range tests {
		s := &Source{
			repos: tt.repos,
			log:   logr.Discard(),
		}

		s.setProgressCompleteWithRepo(tt.index, tt.offset, "")
		gotProgress := s.GetProgress()
		if gotProgress.PercentComplete != tt.wantPercentComplete {
			t.Errorf("s.setProgressCompleteWithRepo() PercentComplete got: %v want: %v", gotProgress.PercentComplete, tt.wantPercentComplete)
		}
		if gotProgress.SectionsCompleted != tt.wantSectionsCompleted {
			t.Errorf("s.setProgressCompleteWithRepo() PercentComplete got: %v want: %v", gotProgress.SectionsCompleted, tt.wantSectionsCompleted)
		}
		if gotProgress.SectionsRemaining != tt.wantSectionsRemaining {
			t.Errorf("s.setProgressCompleteWithRepo() PercentComplete got: %v want: %v", gotProgress.SectionsRemaining, tt.wantSectionsRemaining)
		}
	}
}

func Test_scan_SetProgressComplete(t *testing.T) {
	testCases := []struct {
		name         string
		repos        []string
		wantComplete bool
		wantErr      bool
	}{
		{
			name:         "no repos",
			wantComplete: true,
		},
		{
			name:    "one valid repo",
			repos:   []string{"a"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			src := initTestSource(&sourcespb.GitHub{
				Repositories: tc.repos,
			})
			src.jobPool = &errgroup.Group{}

			_ = src.scan(context.Background(), nil, nil)
			if !tc.wantErr {
				assert.Equal(t, "", src.GetProgress().EncodedResumeInfo)
			}

			gotComplete := src.GetProgress().PercentComplete == 100
			if gotComplete != tc.wantComplete {
				t.Errorf("got: %v, want: %v", gotComplete, tc.wantComplete)
			}
		})
	}
}
