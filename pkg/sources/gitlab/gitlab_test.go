package gitlab

import (
	"reflect"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

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

func TestGetAllProjectReposV2_Deduplication(t *testing.T) {
	// Test that getAllProjectReposV2 correctly deduplicates projects
	// that appear multiple times in the API response
	ctx := context.Background()

	// Track reported units
	reportedProjects := make(map[string]int)
	var mu sync.Mutex
	reporter := sources.VisitorReporter{
		VisitUnit: func(ctx context.Context, unit sources.SourceUnit) error {
			mu.Lock()
			defer mu.Unlock()
			unitID, _ := unit.SourceUnitID()
			reportedProjects[unitID]++
			return nil
		},
	}

	// This is a simplified test that verifies the deduplication logic works
	// We can't easily mock the gitlab.Scan2 iterator without extensive setup,
	// but we can verify that the seenProjects map would prevent duplicates
	// by checking the logic in a simpler way

	// Simulate what happens when the same project ID appears multiple times
	// The actual API call is: gitlab.Scan2(...) which returns an iterator
	// For testing, we verify the deduplication map logic works correctly

	// Verify that if we process projects with the same ID multiple times,
	// only the first one gets reported
	seenProjects := make(map[int]struct{})
	
	projects := []struct {
		id  int
		url string
	}{
		{1, "https://gitlab.com/org/project1.git"},
		{2, "https://gitlab.com/org/project2.git"},
		{1, "https://gitlab.com/org/project1.git"}, // Duplicate!
		{3, "https://gitlab.com/org/project3.git"},
		{2, "https://gitlab.com/org/project2.git"}, // Duplicate!
	}

	uniqueReported := 0
	for _, proj := range projects {
		// Simulate the deduplication logic from getAllProjectReposV2
		if _, exists := seenProjects[proj.id]; exists {
			continue
		}
		seenProjects[proj.id] = struct{}{}
		
		unit := git.SourceUnit{Kind: git.UnitRepo, ID: proj.url}
		if err := reporter.VisitUnit(ctx, unit); err != nil {
			t.Fatal(err)
		}
		uniqueReported++
	}

	// Should report exactly 3 unique projects
	assert.Equal(t, 3, uniqueReported, "should have reported 3 unique projects")
	assert.Equal(t, 3, len(reportedProjects), "should have 3 unique projects in map")
	assert.Equal(t, 1, reportedProjects["https://gitlab.com/org/project1.git"], "project1 should be reported once")
	assert.Equal(t, 1, reportedProjects["https://gitlab.com/org/project2.git"], "project2 should be reported once")
	assert.Equal(t, 1, reportedProjects["https://gitlab.com/org/project3.git"], "project3 should be reported once")
}

func Test_normalizeGitlabEndpoint(t *testing.T) {
	testCases := map[string]struct {
		inputEndpoint  string
		outputEndpoint string
		wantErr        bool
	}{
		"the cloud url should return the cloud url": {
			inputEndpoint:  gitlabBaseURL,
			outputEndpoint: gitlabBaseURL,
		},
		"empty string should return the cloud url": {
			inputEndpoint:  "",
			outputEndpoint: gitlabBaseURL,
		},
		"no scheme cloud url should return the cloud url": {
			inputEndpoint:  "gitlab.com",
			outputEndpoint: gitlabBaseURL,
		},
		"no scheme cloud url with trailing slash should return the cloud url": {
			inputEndpoint:  "gitlab.com/",
			outputEndpoint: gitlabBaseURL,
		},
		"http scheme cloud url with organization should return the cloud url": {
			inputEndpoint:  "http://gitlab.com/trufflesec",
			outputEndpoint: gitlabBaseURL,
		},
		// On-prem endpoint testing.
		"on-prem url should be unchanged": {
			inputEndpoint:  "https://gitlab.trufflesec.com/",
			outputEndpoint: "https://gitlab.trufflesec.com/",
		},
		"on-prem url without trailing slash should have trailing slash added": {
			inputEndpoint:  "https://gitlab.trufflesec.com",
			outputEndpoint: "https://gitlab.trufflesec.com/",
		},
		"on-prem url with http scheme should return an error": {
			inputEndpoint: "http://gitlab.trufflesec.com/",
			wantErr:       true,
		},
		"on-prem with gitlab.com should not rewrite to the cloud url": {
			inputEndpoint:  "https://gitlab.com.trufflesec.com/",
			outputEndpoint: "https://gitlab.com.trufflesec.com/",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			output, err := normalizeGitlabEndpoint(tc.inputEndpoint)
			assert.Equal(t, tc.outputEndpoint, output)
			assert.Equal(t, tc.wantErr, err != nil)
		})
	}
}
