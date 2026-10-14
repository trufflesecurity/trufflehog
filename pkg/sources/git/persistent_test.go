package git

import (
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestPersistentClonePath(t *testing.T) {
	base := t.TempDir()

	t.Run("layout and determinism", func(t *testing.T) {
		p1, err := PersistentClonePath("https://github.com/Org/Repo.git", base)
		require.NoError(t, err)
		p2, err := PersistentClonePath("https://github.com/org/repo", base)
		require.NoError(t, err)
		assert.Equal(t, p1, p2, "github paths are case-insensitive and .git is optional")

		rel, err := filepath.Rel(base, p1)
		require.NoError(t, err)
		parts := strings.Split(rel, string(filepath.Separator))
		require.Len(t, parts, 3)
		assert.Regexp(t, `^[0-9a-f]{12}-github\.com$`, parts[0])
		assert.Regexp(t, `^[0-9a-f]{12}-org$`, parts[1])
		assert.Regexp(t, `^[0-9a-f]{12}-repo$`, parts[2])
	})

	t.Run("no trufflehog prefix", func(t *testing.T) {
		p, err := PersistentClonePath("https://github.com/org/repo.git", base)
		require.NoError(t, err)
		for _, part := range strings.Split(strings.TrimPrefix(p, base), string(filepath.Separator)) {
			assert.False(t, strings.HasPrefix(part, "trufflehog-"), part)
		}
	})

	t.Run("wiki differs from repo but shares the namespace dir", func(t *testing.T) {
		repo, err := PersistentClonePath("https://github.com/org/repo.git", base)
		require.NoError(t, err)
		wiki, err := PersistentClonePath("https://github.com/org/repo.wiki.git", base)
		require.NoError(t, err)
		assert.NotEqual(t, repo, wiki)
		assert.Equal(t, filepath.Dir(repo), filepath.Dir(wiki))
		assert.True(t, strings.HasSuffix(wiki, "-repo.wiki"), wiki)
	})

	t.Run("different hosts and owners do not collide", func(t *testing.T) {
		a, _ := PersistentClonePath("https://github.com/org/repo.git", base)
		b, _ := PersistentClonePath("https://ghe.example.com/org/repo.git", base)
		c, _ := PersistentClonePath("https://github.com/other/repo.git", base)
		assert.NotEqual(t, a, b)
		assert.NotEqual(t, a, c)
		assert.NotEqual(t, filepath.Dir(a), filepath.Dir(c))
	})

	t.Run("case matters on hosts without case-insensitive paths", func(t *testing.T) {
		a, _ := PersistentClonePath("https://git.example.com/Org/Repo.git", base)
		b, _ := PersistentClonePath("https://git.example.com/org/repo.git", base)
		assert.NotEqual(t, a, b)
	})

	t.Run("unsafe names stay inside the clone path", func(t *testing.T) {
		for _, u := range []string{
			"https://git.example.com/org/..",
			"https://git.example.com/../..",
			"https://git.example.com/org/re%20po%0Ax;|*",
			"https://git.example.com/org/" + strings.Repeat("a", 400),
		} {
			p, err := PersistentClonePath(u, base)
			require.NoError(t, err, u)
			assert.True(t, strings.HasPrefix(p, base+string(filepath.Separator)), "%s -> %s", u, p)
			rel, _ := filepath.Rel(base, p)
			parts := strings.Split(rel, string(filepath.Separator))
			assert.Len(t, parts, 3, "%s -> %s", u, p)
			for _, part := range parts {
				assert.NotContains(t, part, " ")
				assert.NotContains(t, part, "\n")
				assert.LessOrEqual(t, len(part), persistentHashLen+1+persistentNameMax)
			}
		}
	})

	t.Run("missing repository name is an error", func(t *testing.T) {
		_, err := PersistentClonePath("https://github.com/", base)
		assert.Error(t, err)
	})
}

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-C", dir}, args...)
	out, err := exec.Command("git", full...).CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

func commitT(t *testing.T, dir, file, content string) string {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644))
	gitT(t, dir, "add", file)
	gitT(t, dir, "commit", "-m", content)
	return gitT(t, dir, "rev-parse", "HEAD")
}

func newUpstream(t *testing.T) (dir, url string) {
	t.Helper()
	dir = t.TempDir()
	gitT(t, dir, "init", "-b", "main")
	return dir, "file://" + dir
}

func objectExists(t *testing.T, repoPath, sha string) bool {
	t.Helper()
	return exec.Command("git", "-C", repoPath, "cat-file", "-e", sha+"^{commit}").Run() == nil
}

func TestCloneOrFetchRepo(t *testing.T) {
	ctx := context.Background()

	t.Run("clones, then fetches, never losing overwritten or deleted refs", func(t *testing.T) {
		up, upURL := newUpstream(t)
		a := commitT(t, up, "f", "A")
		gitT(t, up, "branch", "feature")

		clones := t.TempDir()
		path, repo, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		require.NotNil(t, repo)

		want, err := PersistentClonePath(upURL, clones)
		require.NoError(t, err)
		assert.Equal(t, want, path)
		assert.NoDirExists(t, path+partialCloneSuffix)
		assert.Equal(t, a, gitT(t, path, "rev-parse", "refs/remotes/origin/main"))

		// Fast-forward upstream.
		b := commitT(t, up, "f", "B")
		path2, _, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		assert.Equal(t, path, path2)
		assert.Equal(t, b, gitT(t, path, "rev-parse", "refs/remotes/origin/main"))

		// Force-push main to a commit that doesn't contain B, and delete a branch.
		gitT(t, up, "reset", "--hard", a)
		c := commitT(t, up, "f", "C")
		gitT(t, up, "branch", "-D", "feature")

		_, _, err = CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		assert.Equal(t, c, gitT(t, path, "rev-parse", "refs/remotes/origin/main"))

		assert.True(t, objectExists(t, path, b), "overwritten tip must still exist")
		assert.Equal(t, b, gitT(t, path, "rev-parse", preservedRefPrefix+b), "overwritten tip must stay referenced")
		assert.Equal(t, a, gitT(t, path, "rev-parse", "refs/remotes/origin/feature"), "refs deleted upstream are not pruned")
		assert.Contains(t, gitT(t, path, "log", "--all", "--format=%H"), b, "scan with --all sees the overwritten commit")
	})

	t.Run("origin carries no credentials", func(t *testing.T) {
		up, upURL := newUpstream(t)
		commitT(t, up, "f", "A")

		clones := t.TempDir()
		path, _, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		cfg, err := os.ReadFile(filepath.Join(path, ".git", "config"))
		require.NoError(t, err)
		assert.NotContains(t, string(cfg), "@")
	})

	t.Run("fetches into a mirror clone", func(t *testing.T) {
		up, upURL := newUpstream(t)
		a := commitT(t, up, "f", "A")

		clones := t.TempDir()
		path, err := PersistentClonePath(upURL, clones)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		out, err := exec.Command("git", "clone", "--mirror", "--quiet", upURL, path).CombinedOutput()
		require.NoError(t, err, string(out))

		commitT(t, up, "f", "B")
		gitT(t, up, "reset", "--hard", a)
		c := commitT(t, up, "f", "C")

		_, _, err = CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		assert.Equal(t, c, gitT(t, path, "rev-parse", "refs/heads/main"))
		assert.Equal(t, a, gitT(t, path, "rev-parse", preservedRefPrefix+a), "previous tip is preserved")
		assert.True(t, objectExists(t, path, a))
	})

	t.Run("an existing directory that is not a git repo is left alone", func(t *testing.T) {
		up, upURL := newUpstream(t)
		commitT(t, up, "f", "A")

		clones := t.TempDir()
		path, err := PersistentClonePath(upURL, clones)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(path, 0o755))
		marker := filepath.Join(path, "keep")
		require.NoError(t, os.WriteFile(marker, []byte("x"), 0o644))

		_, _, err = CloneOrFetchRepo(ctx, nil, upURL, clones)
		assert.Error(t, err)
		assert.FileExists(t, marker)
	})

	t.Run("an incomplete clone from an earlier run is replaced", func(t *testing.T) {
		up, upURL := newUpstream(t)
		commitT(t, up, "f", "A")

		clones := t.TempDir()
		path, err := PersistentClonePath(upURL, clones)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(path+partialCloneSuffix, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(path+partialCloneSuffix, "junk"), []byte("x"), 0o644))

		_, repo, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		require.NotNil(t, repo)
		assert.NoDirExists(t, path+partialCloneSuffix)
	})

	t.Run("requires a clone path", func(t *testing.T) {
		_, _, err := CloneOrFetchRepo(ctx, nil, "https://github.com/org/repo.git", "")
		assert.Error(t, err)
	})
}

func TestRefsDigest(t *testing.T) {
	ctx := context.Background()
	up, upURL := newUpstream(t)
	commitT(t, up, "f", "A")

	clones := t.TempDir()
	path, _, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
	require.NoError(t, err)

	d1, err := RefsDigest(ctx, path)
	require.NoError(t, err)

	t.Run("unchanged after a no-op fetch, even though refs/trufflehog changes", func(t *testing.T) {
		_, _, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		d2, err := RefsDigest(ctx, path)
		require.NoError(t, err)
		assert.Equal(t, d1, d2)
	})

	t.Run("changes when upstream changes", func(t *testing.T) {
		commitT(t, up, "f", "B")
		_, _, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
		require.NoError(t, err)
		d3, err := RefsDigest(ctx, path)
		require.NoError(t, err)
		assert.NotEqual(t, d1, d3)
	})

	t.Run("recorded digest round-trips", func(t *testing.T) {
		assert.Empty(t, ScannedRefsDigest(ctx, path))
		require.NoError(t, SetScannedRefsDigest(ctx, path, d1))
		assert.Equal(t, d1, ScannedRefsDigest(ctx, path))
	})
}

func TestSameRemote(t *testing.T) {
	parse := func(s string) *neturl.URL {
		u, err := GitURLParse(s)
		require.NoError(t, err)
		return u
	}
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "https://github.com/org/repo.git", "https://github.com/org/repo.git", true},
		{".git optional and github paths case-insensitive", "https://github.com/Org/Repo", "https://github.com/org/repo.git", true},
		{"embedded credentials ignored", "https://user:pw@github.com/org/repo.git", "https://github.com/org/repo.git", true},
		{"scheme downgrade", "http://github.com/org/repo.git", "https://github.com/org/repo.git", false},
		{"different host", "https://evil.example.com/org/repo.git", "https://github.com/org/repo.git", false},
		{"different repo", "https://github.com/org/other.git", "https://github.com/org/repo.git", false},
		{"case matters off github", "https://git.example.com/Org/Repo.git", "https://git.example.com/org/repo.git", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sameRemote(parse(tt.a), parse(tt.b)))
		})
	}
}

func TestFetchArgs(t *testing.T) {
	remote, err := neturl.Parse("https://github.com/org/repo.git")
	require.NoError(t, err)

	t.Run("credentials are scoped to the expected remote", func(t *testing.T) {
		args := fetchArgs(neturl.UserPassword("user", "secret"), remote, "/clones/x")
		require.GreaterOrEqual(t, len(args), 2)
		assert.Equal(t, "-c", args[0])
		assert.True(t, strings.HasPrefix(args[1], "http.https://github.com/org/repo.git.extraHeader=Authorization: Basic "), args[1])
		assert.NotContains(t, strings.Join(args[2:], " "), "secret")
		assert.Contains(t, args, "--no-prune")
	})

	t.Run("no header without credentials", func(t *testing.T) {
		args := fetchArgs(nil, remote, "/clones/x")
		assert.NotContains(t, strings.Join(args, " "), "extraHeader")
	})
}

func TestCloneOrFetchRepo_RefusesForeignOrigin(t *testing.T) {
	ctx := context.Background()
	up, upURL := newUpstream(t)
	commitT(t, up, "f", "A")
	other, otherURL := newUpstream(t)
	commitT(t, other, "f", "other")

	clones := t.TempDir()
	path, _, err := CloneOrFetchRepo(ctx, nil, upURL, clones)
	require.NoError(t, err)

	gitT(t, path, "remote", "set-url", "origin", otherURL)
	before := gitT(t, path, "rev-parse", "refs/remotes/origin/main")

	for _, userInfo := range []*neturl.Userinfo{nil, neturl.UserPassword("u", "p")} {
		_, _, err = CloneOrFetchRepo(ctx, userInfo, upURL, clones)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not the expected repository")
		assert.NotContains(t, err.Error(), otherURL)
	}
	assert.Equal(t, before, gitT(t, path, "rev-parse", "refs/remotes/origin/main"), "nothing was fetched")
}
