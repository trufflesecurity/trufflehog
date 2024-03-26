package github

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v57/github"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
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
	if err := s.Init(context.Background(), "test - github", 0, 1337, false, conn, 1); err != nil {
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

	err := source.Init(context.Background(), "test - github", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	// TODO: test error case
}

func TestAddReposByOrg(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{
			{"clone_url": "https://github.com/super-secret-repo.git", "full_name": "super-secret-repo"},
			{"clone_url": "https://github.com/super-secret-repo2.git", "full_name": "secret/super-secret-repo2"},
		})

	s := initTestSource(&sourcespb.GitHub{
		Credential: &sourcespb.GitHub_Token{
			Token: "super secret token",
		},
		Repositories: nil,
		IgnoreRepos:  []string{"secret/super-*-repo2"},
	})
	// gock works here because github.NewClient is using the default HTTP Transport
	err := s.getReposByOrg(context.Background(), "super-secret-org")
	assert.Nil(t, err)
	assert.Equal(t, 1, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("super-secret-repo")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestAddReposByOrg_IncludeRepos(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{
			{"clone_url": "https://github.com/super-secret-repo.git", "full_name": "secret/super-secret-repo"},
			{"clone_url": "https://github.com/super-secret-repo2.git", "full_name": "secret/super-secret-repo2"},
			{"clone_url": "https://github.com/super-secret-repo2.git", "full_name": "secret/not-super-secret-repo"},
		})

	s := initTestSource(&sourcespb.GitHub{
		Credential: &sourcespb.GitHub_Token{
			Token: "super secret token",
		},
		Repositories:  []string{"secret/super*"},
		Organizations: []string{"super-secret-org"},
	})
	// gock works here because github.NewClient is using the default HTTP Transport
	err := s.getReposByOrg(context.Background(), "super-secret-org")
	assert.Nil(t, err)
	assert.Equal(t, 2, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("secret/super-secret-repo")
	assert.True(t, ok)
	ok = s.filteredRepoCache.Exists("secret/super-secret-repo2")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestAddReposByUser(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{
			{"clone_url": "https://github.com/super-secret-repo.git", "full_name": "super-secret-repo"},
			{"clone_url": "https://github.com/super-secret-repo2.git", "full_name": "secret/super-secret-repo2"},
		})

	s := initTestSource(&sourcespb.GitHub{
		Credential: &sourcespb.GitHub_Token{
			Token: "super secret token",
		},
		IgnoreRepos: []string{"secret/super-secret-repo2"},
	})
	err := s.getReposByUser(context.Background(), "super-secret-user")
	assert.Nil(t, err)
	assert.Equal(t, 1, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("super-secret-repo")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestAddGistsByUser(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON([]map[string]string{{"git_pull_url": "https://githug.com/super-secret-gist.git", "id": "super-secret-gist"}})

	s := initTestSource(nil)
	err := s.addUserGistsToCache(context.Background(), "super-secret-user")
	assert.Nil(t, err)
	assert.Equal(t, 1, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("super-secret-gist")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestAddMembersByOrg(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/org1/members").
		Reply(200).
		JSON([]map[string]string{
			{"login": "testman1"},
			{"login": "testman2"},
		})

	s := initTestSource(nil)
	err := s.addMembersByOrg(context.Background(), "org1")
	assert.Nil(t, err)
	assert.Equal(t, 2, len(s.memberCache))
	_, ok := s.memberCache["testman1"]
	assert.True(t, ok)
	_, ok = s.memberCache["testman2"]
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestAddMembersByApp(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/app/installations").
		Reply(200).
		JSON([]map[string]any{
			{"account": map[string]string{"login": "super-secret-org", "type": "Organization"}},
		})
	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/members").
		Reply(200).
		JSON([]map[string]any{
			{"login": "ssm1"},
			{"login": "ssm2"},
			{"login": "ssm3"},
		})

	s := initTestSource(nil)
	err := s.addMembersByApp(context.Background(), github.NewClient(nil))
	assert.Nil(t, err)
	assert.Equal(t, 3, len(s.memberCache))
	_, ok := s.memberCache["ssm1"]
	assert.True(t, ok)
	_, ok = s.memberCache["ssm2"]
	assert.True(t, ok)
	_, ok = s.memberCache["ssm3"]
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestAddReposByApp(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/installation/repositories").
		Reply(200).
		JSON(map[string]any{
			"repositories": []map[string]string{
				{"clone_url": "https://github/ssr1.git", "full_name": "ssr1"},
				{"clone_url": "https://github/ssr2.git", "full_name": "ssr2"},
			},
		})

	s := initTestSource(nil)
	err := s.getReposByApp(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, 2, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("ssr1")
	assert.True(t, ok)
	ok = s.filteredRepoCache.Exists("ssr2")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestAddOrgsByUser(t *testing.T) {
	defer gock.Off()

	// NOTE: addOrgsByUser calls /user/orgs to get the orgs of the
	// authenticated user
	gock.New("https://api.github.com").
		Get("/user/orgs").
		Reply(200).
		JSON([]map[string]any{
			{"login": "sso2"},
		})

	s := initTestSource(nil)
	s.addOrgsByUser(context.Background(), "super-secret-user")
	assert.Equal(t, 1, s.orgsCache.Count())
	ok := s.orgsCache.Exists("sso2")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func TestNormalizeRepos(t *testing.T) {
	defer gock.Off()

	tests := []struct {
		name     string
		setup    func()
		repos    []string
		expected map[string]struct{}
		wantErr  bool
	}{
		{
			name:  "repo url",
			setup: func() {},
			repos: []string{"https://github.com/super-secret-user/super-secret-repo"},
			expected: map[string]struct{}{
				"https://github.com/super-secret-user/super-secret-repo.git": {},
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
			expected: map[string]struct{}{},
			wantErr:  true,
		},
		{
			name:     "unexpected format",
			setup:    func() {},
			repos:    []string{"/foo/"},
			expected: map[string]struct{}{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer gock.Off()
			tt.setup()
			s := initTestSource(nil)

			got, err := s.normalizeRepo(tt.repos[0])
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeRepo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != "" {
				for k := range tt.expected {
					assert.Equal(t, got, k)
				}
			}
			res := make(map[string]struct{}, s.filteredRepoCache.Count())
			for _, v := range s.filteredRepoCache.Keys() {
				res[v] = struct{}{}
			}

			if got == "" && !cmp.Equal(res, tt.expected) {
				t.Errorf("normalizeRepo() got = %v, want %v", s.repos, tt.expected)
			}
		})
	}
}

func TestHandleRateLimit(t *testing.T) {
	s := initTestSource(nil)
	assert.False(t, s.handleRateLimit(nil))

	// Request
	reqUrl, _ := url.Parse("https://github.com/trufflesecurity/trufflehog")
	res := &github.Response{
		Response: &http.Response{
			StatusCode: 429,
			Header:     make(http.Header),
			Request: &http.Request{
				Method: "GET",
				URL:    reqUrl,
			},
		},
	}
	res.Header.Set("x-ratelimit-remaining", "0")
	res.Header.Set("x-ratelimit-reset", strconv.FormatInt(time.Now().Unix()+1, 10))

	// Error
	resetTime := github.Timestamp{
		Time: time.Now().Add(time.Millisecond),
	}
	err := &github.RateLimitError{
		Rate: github.Rate{
			Limit:     5000,
			Remaining: 0,
			Reset:     resetTime,
		},
		Response: res.Response,
		Message:  "Too Many Requests",
	}

	assert.True(t, s.handleRateLimit(err))
}

func TestEnumerateUnauthenticated(t *testing.T) {
	defer gock.Off()

	apiEndpoint := "https://api.github.com"
	gock.New(apiEndpoint).
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-repo.git", "full_name": "super-secret-repo"}})

	s := initTestSource(nil)
	s.orgsCache = memory.New()
	s.orgsCache.Set("super-secret-org", "super-secret-org")
	s.enumerateUnauthenticated(context.Background(), apiEndpoint)
	assert.Equal(t, 1, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("super-secret-repo")
	assert.True(t, ok)
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
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-repo.git", "full_name": "super-secret-repo"}})

	gock.New("https://api.github.com").
		Get("/user/orgs").
		MatchParam("per_page", "100").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-repo.git", "full_name": "super-secret-repo"}})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON([]map[string]string{{"git_pull_url": "https://github.com/super-secret-gist.git", "id": "super-secret-gist"}})

	s := initTestSource(nil)
	err := s.enumerateWithToken(context.Background(), "https://api.github.com", "token")
	assert.Nil(t, err)
	assert.Equal(t, 2, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("super-secret-repo")
	assert.True(t, ok)
	ok = s.filteredRepoCache.Exists("super-secret-gist")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func BenchmarkEnumerateWithToken(b *testing.B) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]string{"login": "super-secret-user"})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-repo.git"}})

	gock.New("https://api.github.com").
		Get("/user/orgs").
		MatchParam("per_page", "100").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-repo.git"}})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON([]map[string]string{{"git_pull_url": "https://github.com/super-secret-gist.git"}})

	s := initTestSource(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.enumerateWithToken(context.Background(), "https://api.github.com", "token")
	}
}

func TestEnumerate(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]string{"login": "super-secret-user"})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-user/super-secret-repo.git", "full_name": "super-secret-user/super-secret-repo"}})

	gock.New("https://api.github.com").
		Get("/repos/super-secret-user/super-secret-repo").
		Reply(200).
		JSON(`{"owner": {"login": "super-secret-user"}, "name": "super-secret-repo", "full_name": "super-secret-user/super-secret-repo", "has_wiki": false, "size": 1}`)

	gock.New("https://api.github.com").
		Get("/user/orgs").
		MatchParam("per_page", "100").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-user/super-secret-repo.git", "full_name": "super-secret-user/super-secret-repo"}})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON(`[{"git_pull_url": "https://gist.github.com/2801a2b0523099d0614a951579d99ba9.git", "id": "2801a2b0523099d0614a951579d99ba9"}]`)

	s := initTestSource(&sourcespb.GitHub{
		Credential: &sourcespb.GitHub_Token{
			Token: "super secret token",
		},
	})

	_, err := s.enumerate(context.Background(), "https://api.github.com")
	assert.Nil(t, err)
	assert.Equal(t, 2, s.filteredRepoCache.Count())
	ok := s.filteredRepoCache.Exists("super-secret-user/super-secret-repo")
	assert.True(t, ok)
	ok = s.filteredRepoCache.Exists("2801a2b0523099d0614a951579d99ba9")
	assert.True(t, ok)
	assert.True(t, gock.IsDone())
}

func setupMocks(b *testing.B) {
	b.Helper()

	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]string{"login": "super-secret-user"})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON(mockRepos())

	gock.New("https://api.github.com").
		Get("/user/orgs").
		MatchParam("per_page", "100").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "https://github.com/super-secret-repo.git"}})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON(mockGists())
}

func mockRepos() []map[string]string {
	res := make([]map[string]string, 0, 10000)
	for i := 0; i < 10000; i++ {
		res = append(res, map[string]string{"clone_url": fmt.Sprintf("https://githu/super-secret-repo-%d.git", i)})
	}
	return res
}

func mockGists() []map[string]string {
	res := make([]map[string]string, 0, 100)
	for i := 0; i < 100; i++ {
		res = append(res, map[string]string{"git_pull_url": fmt.Sprintf("https://githu/super-secret-gist-%d.git", i)})
	}
	return res
}

func BenchmarkEnumerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		s := initTestSource(&sourcespb.GitHub{
			Credential: &sourcespb.GitHub_Token{
				Token: "super secret token",
			},
		})
		setupMocks(b)

		b.StartTimer()
		_, _ = s.enumerate(context.Background(), "https://api.github.com")
	}
}

func TestEnumerateWithToken_IncludeRepos(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]string{"login": "super-secret-user"})

	s := initTestSource(nil)
	s.repos = []string{"some-special-repo"}

	err := s.enumerateWithToken(context.Background(), "https://api.github.com", "token")
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
		context.Background(),
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
			name:         "one valid repo",
			repos:        []string{"a"},
			wantComplete: true,
			wantErr:      true,
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

func TestGetRepoURLParts(t *testing.T) {
	tests := []string{
		"https://github.com/trufflesecurity/trufflehog.git",
		"git+https://github.com/trufflesecurity/trufflehog.git",
		//"git@github.com:trufflesecurity/trufflehog.git",
		"ssh://github.com/trufflesecurity/trufflehog.git",
		"ssh://git@github.com/trufflesecurity/trufflehog.git",
		"git+ssh://git@github.com/trufflesecurity/trufflehog.git",
		"git://github.com/trufflesecurity/trufflehog.git",
	}
	expected := []string{"github.com", "trufflesecurity", "trufflehog"}
	for _, tt := range tests {
		_, parts, err := getRepoURLParts(tt)
		if err != nil {
			t.Fatalf("failed: %v", err)
		}
		assert.Equal(t, expected, parts)
	}
}

func TestGetGistID(t *testing.T) {
	tests := []struct {
		trimmedURL []string
		expected   string
	}{
		{[]string{"https://gist.github.com", "12345"}, "12345"},
		{[]string{"https://gist.github.com", "owner", "12345"}, "12345"},
	}

	for _, tt := range tests {
		got := extractGistID(tt.trimmedURL)
		assert.Equal(t, tt.expected, got)
	}
}
