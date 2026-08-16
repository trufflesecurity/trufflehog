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

// protoEnvelope mirrors how the platform stores a scan unit: the SourceUnit
// proto marshalled to JSON, carrying the original enumerated payload in the
// base64 unit_data field. Reproducing it here proves RepoUnit.InstallationID
// survives the enumerate/scan boundary (the fix for INT-790).
func protoEnvelope(t *testing.T, kind, id, display string, payload any) []byte {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)
	envelope := map[string]any{
		"id":        id,
		"kind":      kind,
		"display":   display,
		"unit_data": base64.StdEncoding.EncodeToString(payloadBytes),
	}
	out, err := json.Marshal(envelope)
	require.NoError(t, err)
	return out
}

func TestUnmarshalSourceUnitPreservesInstallationID(t *testing.T) {
	s := &Source{}

	t.Run("proto envelope with unit_data recovers installation id", func(t *testing.T) {
		data := protoEnvelope(t, "repo", "https://github.com/spotify/backstage.git", "spotify/backstage",
			RepoUnit{Name: "spotify/backstage", URL: "https://github.com/spotify/backstage.git", InstallationID: 2448})

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

	t.Run("legacy proto envelope without unit_data has no installation id", func(t *testing.T) {
		// In-flight units enumerated before the installation_id field existed.
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
			Name: "acme/widgets", URL: "https://github.com/acme/widgets.git", InstallationID: 111,
		})
		require.NoError(t, err)

		unit, err := s.UnmarshalSourceUnit(data)
		require.NoError(t, err)

		repoUnit, ok := unit.(RepoUnit)
		require.True(t, ok)
		assert.Equal(t, int64(111), repoUnit.InstallationID)
	})

	t.Run("gist unit round trips", func(t *testing.T) {
		data := protoEnvelope(t, "gist", "https://gist.github.com/abc.git", "abc",
			GistUnit{Name: "abc", URL: "https://gist.github.com/abc.git"})

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

// TestProcessReposEmitsInstallationID verifies that scan-all-installations
// enumeration records the owning installation on each emitted RepoUnit, so the
// scan job can use it directly instead of re-deriving the mapping.
func TestProcessReposEmitsInstallationID(t *testing.T) {
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

// TestApplyUnitInstallation is the INT-790 regression at the consumption side:
// a unit that already carries its installation maps directly, so ChunkUnit does
// not fall back to re-listing every installation's repos.
func TestApplyUnitInstallation(t *testing.T) {
	newConnector := func() *appConnector {
		return &appConnector{installationID: 1, repoInstallationMap: make(map[string]int64)}
	}
	const repoURL = "https://github.com/spotify/backstage.git"

	t.Run("uses the installation carried on the unit", func(t *testing.T) {
		connector := newConnector()
		unit := RepoUnit{Name: "spotify/backstage", URL: repoURL, InstallationID: 2448}

		handled := (&Source{}).applyUnitInstallation(connector, unit, repoURL)

		require.True(t, handled, "must not fall back to re-deriving the mapping")
		id, mapped := connector.installationIDForRepo(repoURL)
		assert.True(t, mapped)
		assert.Equal(t, int64(2448), id)
	})

	t.Run("falls back when the unit carries no installation", func(t *testing.T) {
		connector := newConnector()
		unit := RepoUnit{Name: "spotify/backstage", URL: repoURL}

		handled := (&Source{}).applyUnitInstallation(connector, unit, repoURL)

		assert.False(t, handled)
		_, mapped := connector.installationIDForRepo(repoURL)
		assert.False(t, mapped, "caller must derive the mapping instead")
	})

	t.Run("falls back for non-repo units", func(t *testing.T) {
		connector := newConnector()
		unit := sources.CommonSourceUnit{Kind: "repo", ID: repoURL}

		handled := (&Source{}).applyUnitInstallation(connector, unit, repoURL)

		assert.False(t, handled)
	})
}
