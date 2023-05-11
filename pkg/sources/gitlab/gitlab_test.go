package gitlab

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("GITLAB_TOKEN")
	basicUser := secret.MustGetField("GITLAB_USER")
	basicPass := secret.MustGetField("GITLAB_PASS")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitLab
	}
	tests := []struct {
		name             string
		init             init
		wantChunk        *sources.Chunk
		wantReposScanned int
		wantErr          bool
	}{
		{
			name: "token auth, enumerate repo, with explicit ignore",
			init: init{
				name: "test source",
				connection: &sourcespb.GitLab{
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
					IgnoreRepos: []string{"tes1188/learn-gitlab"},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source",
			},
			wantReposScanned: 2,
		},
		{
			name: "token auth, enumerate repo, with glob ignore",
			init: init{
				name: "test source",
				connection: &sourcespb.GitLab{
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
					IgnoreRepos: []string{"tes1188/*-gitlab"},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source",
			},
			wantReposScanned: 2,
		},
		{
			name: "token auth, scoped repo",
			init: init{
				name: "test source scoped",
				connection: &sourcespb.GitLab{
					Repositories: []string{"https://gitlab.com/testermctestface/testy.git"},
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source scoped",
			},
			wantReposScanned: 1,
		},
		{
			name: "basic auth, scoped repo",
			init: init{
				name: "test source basic auth scoped",
				connection: &sourcespb.GitLab{
					Repositories: []string{"https://gitlab.com/testermctestface/testy.git"},
					Credential: &sourcespb.GitLab_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: basicUser,
							Password: basicPass,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source basic auth scoped",
			},
			wantReposScanned: 1,
		},
		{
			name: "basic auth access token, scoped repo",
			init: init{
				name: "test source basic auth access token scoped",
				connection: &sourcespb.GitLab{
					Repositories: []string{"https://gitlab.com/testermctestface/testy.git"},
					Credential: &sourcespb.GitLab_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: basicUser,
							Password: token,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source basic auth access token scoped",
			},
			wantReposScanned: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 10)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()
			var chunkCnt int
			// Commits don't come in a deterministic order, so remove metadata comparison
			for gotChunk := range chunksCh {
				chunkCnt++
				gotChunk.Data = nil
				gotChunk.SourceMetadata = nil
				if diff := pretty.Compare(gotChunk, tt.wantChunk); diff != "" {
					t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
				}
			}

			assert.Equal(t, tt.wantReposScanned, len(s.repos))
			if chunkCnt < 1 {
				t.Errorf("0 chunks scanned.")
			}
		})
	}
}

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

	s := &Source{repos: []string{}}

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

func Test_scanRepos_SetProgressComplete(t *testing.T) {
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
			repos:        []string{"repo"},
			wantComplete: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			src := &Source{
				repos: tc.repos,
			}
			src.jobPool = &errgroup.Group{}
			src.scanOptions = &git.ScanOptions{}

			_ = src.scanRepos(context.Background(), nil)
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
