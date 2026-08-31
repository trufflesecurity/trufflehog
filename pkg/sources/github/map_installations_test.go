package github

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// This is meant to track APIUnitReporter.UnitOK in scanner/cmd/scanner/pipeline.go
// precisely
func newMarshalledRepoUnit(t *testing.T, su sources.SourceUnit) []byte {
	t.Helper()

	id, kind := su.SourceUnitID()

	unitData, err := json.Marshal(su)
	require.NoError(t, err)

	// [CG] This additional base64 encoding mimics the pipeline's behavior
	unitData = []byte(base64.StdEncoding.EncodeToString(unitData))

	out, err := json.Marshal(map[string]any{
		"id":        id,
		"kind":      string(kind),
		"display":   su.Display(),
		"unit_data": unitData,
	})
	require.NoError(t, err)

	return out
}

func TestGitHub_UnmarshalSourceUnit(t *testing.T) {
	s := &Source{}

	t.Run("source unit with unit_data recovers installation id", func(t *testing.T) {
		data := newMarshalledRepoUnit(t, RepoUnit{
			Name:           "spotify/backstage",
			URL:            "https://github.com/spotify/backstage.git",
			InstallationID: 2448,
		})

		unit, err := s.UnmarshalSourceUnit(data)
		require.NoError(t, err)

		repoUnit, ok := unit.(RepoUnit)
		require.True(t, ok, "expected a RepoUnit so ChunkUnit can read the installation id")
		assert.Equal(t, "https://github.com/spotify/backstage.git", repoUnit.URL)
		assert.Equal(t, "spotify/backstage", repoUnit.Name)
		assert.Equal(t, int64(2448), repoUnit.InstallationID)

		id, kind := unit.SourceUnitID()
		assert.Equal(t, "https://github.com/spotify/backstage.git", id)
		assert.EqualValues(t, "repo", kind)
	})

	t.Run("legacy source unit without unit_data has no installation id", func(t *testing.T) {
		data, err := json.Marshal(map[string]any{
			"id":      "https://github.com/acme/widgets.git",
			"kind":    "repo",
			"display": "acme/widgets",
		})
		require.NoError(t, err)

		unit, err := s.UnmarshalSourceUnit(data)
		require.NoError(t, err)

		repoUnit, ok := unit.(RepoUnit)
		require.True(t, ok)
		assert.Equal(t, "https://github.com/acme/widgets.git", repoUnit.URL)
		assert.Equal(t, "acme/widgets", repoUnit.Name)
		assert.Zero(t, repoUnit.InstallationID, "legacy units fall back to deriving the installation")
	})

	t.Run("full enumeration payload", func(t *testing.T) {
		data, err := json.Marshal(RepoUnit{
			Name:           "acme/widgets",
			URL:            "https://github.com/acme/widgets.git",
			InstallationID: 111,
		})
		require.NoError(t, err)

		unit, err := s.UnmarshalSourceUnit(data)
		require.NoError(t, err)

		repoUnit, ok := unit.(RepoUnit)
		require.True(t, ok)
		assert.Equal(t, int64(111), repoUnit.InstallationID)
	})

	t.Run("gist unit round trips", func(t *testing.T) {
		data := newMarshalledRepoUnit(t, GistUnit{Name: "abc", URL: "https://gist.github.com/abc.git"})

		unit, err := s.UnmarshalSourceUnit(data)
		require.NoError(t, err)

		_, ok := unit.(GistUnit)
		require.True(t, ok)
		_, kind := unit.SourceUnitID()
		assert.EqualValues(t, "gist", kind)
	})

	t.Run("rejects unrecognized payload", func(t *testing.T) {
		_, err := s.UnmarshalSourceUnit([]byte(`{"unrelated":"value"}`))
		require.Error(t, err)
	})
}

// Ensure we store installation IDs when enumerating
func TestGitHub_ProcessReposEmitsInstallationID(t *testing.T) {
	ctx := context.Background()

	connector := &appConnector{
		installationID:      1,
		repoInstallationMap: make(map[string]int64),
	}
	s := &Source{
		conn:              &sourcespb.GitHub{ScanAllInstallations: true},
		connector:         connector,
		filteredRepoCache: &filteredRepoCache{Cache: simple.NewCache[string]()},
		repoInfoCache:     newRepoInfoCache(),
	}

	const installID int64 = 2448
	repo := &github.Repository{
		Name:     github.String("backstage"),
		FullName: github.String("spotify/backstage"),
		CloneURL: github.String("https://github.com/spotify/backstage.git"),
		Owner:    &github.User{Login: github.String("spotify"), Type: github.String("Organization")},
	}

	// Mirror enumerateAllInstallationRepos: the lister records the installation
	// for each repo in a page before processRepos emits the units for it.
	page := 0
	listRepos := func(ctx context.Context, _ string, _ repoListOptions) ([]*github.Repository, *github.Response, error) {
		page++
		if page > 1 {
			return nil, &github.Response{}, nil
		}
		connector.setRepoInstallationForRepoName(repo.GetCloneURL(), repo.GetName(), installID)
		return []*github.Repository{repo}, &github.Response{}, nil
	}

	var units []sources.SourceUnit
	reporter := sources.VisitorReporter{
		VisitUnit: func(_ context.Context, u sources.SourceUnit) error {
			units = append(units, u)
			return nil
		},
	}

	err := s.processRepos(ctx, "spotify", reporter, listRepos, &appListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	})
	require.NoError(t, err)

	require.Len(t, units, 1)
	repoUnit, ok := units[0].(RepoUnit)
	require.True(t, ok)
	assert.Equal(t, "https://github.com/spotify/backstage.git", repoUnit.URL)
	assert.Equal(t, installID, repoUnit.InstallationID)
}
