package git

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

const (
	persistentHashLen  = 12
	persistentNameMax  = 100
	partialCloneSuffix = ".partial"

	// trufflehogRefPrefix holds refs owned by trufflehog; it is excluded from ref digests and tip preservation.
	trufflehogRefPrefix = "refs/trufflehog/"
	// preservedRefPrefix refs keep every previously seen ref tip reachable so a forced fetch never orphans commits.
	preservedRefPrefix = trufflehogRefPrefix + "preserved/"
	// packRefsThreshold is the number of newly created preserved refs above which loose refs are packed.
	packRefsThreshold = 500

	scannedRefsDigestKey = "trufflehog.scannedRefsDigest"
)

// PersistentClonePath returns the deterministic directory a repository is kept in when persistent clones are enabled:
// <clonePath>/<hostHash>-<host>/<namespaceHash>-<namespace>/<repoHash>-<repo>.
// The hashes identify the directories; the trailing names are only for humans.
func PersistentClonePath(gitURL, clonePath string) (string, error) {
	u, err := GitURLParse(gitURL)
	if err != nil {
		return "", fmt.Errorf("could not parse clone url: %w", err)
	}

	host := strings.ToLower(u.Host)

	repoPath := strings.Trim(u.Path, "/")
	repoPath = strings.Trim(strings.TrimSuffix(repoPath, gitDirName), "/")
	if hasCaseInsensitivePaths(host) {
		repoPath = strings.ToLower(repoPath)
	}

	namespace, repo := "", repoPath
	if idx := strings.LastIndex(repoPath, "/"); idx >= 0 {
		namespace, repo = repoPath[:idx], repoPath[idx+1:]
	}
	if repo == "" {
		return "", fmt.Errorf("clone url has no repository name")
	}

	return filepath.Join(
		clonePath,
		persistentDirName(host, host),
		persistentDirName(host+"/"+namespace, namespace),
		persistentDirName(host+"/"+repoPath, repo),
	), nil
}

// hasCaseInsensitivePaths reports whether owner/repo paths on the host are case-insensitive.
func hasCaseInsensitivePaths(host string) bool {
	return host == "github.com" || strings.HasSuffix(host, ".ghe.com")
}

func persistentDirName(hashInput, name string) string {
	sum := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(sum[:])[:persistentHashLen] + "-" + normalizeDirName(name)
}

// normalizeDirName makes name safe to use as a single path element.
func normalizeDirName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, name)
	if len(name) > persistentNameMax {
		name = name[:persistentNameMax]
	}
	if name == "" {
		return "_"
	}
	return name
}

// CloneOrFetchRepo clones gitURL into its persistent directory under clonePath, or, if a clone from an earlier run is
// already there, fetches new data into it. Nothing is ever pruned or deleted from an existing clone: before every fetch
// all current ref tips are preserved under refs/trufflehog/preserved/, so refs that get overwritten upstream still
// keep their old commits reachable.
//
// Credentials are sent as an HTTP header scoped to gitURL and never stored in the clone's configuration. A fetch is
// refused if the clone's origin is not gitURL, so a swapped or edited clone can't redirect credentials elsewhere.
func CloneOrFetchRepo(ctx context.Context, userInfo *url.Userinfo, gitURL, clonePath string) (string, *git.Repository, error) {
	if clonePath == "" {
		return "", nil, fmt.Errorf("persistent clones require a clone path")
	}

	path, err := PersistentClonePath(gitURL, clonePath)
	if err != nil {
		return "", nil, err
	}
	timeout := time.Duration(feature.GitCloneTimeoutDuration.Load())

	_, statErr := os.Stat(path)
	switch {
	case statErr == nil:
		if _, err := RepoFromPath(path); err != nil {
			return "", nil, fmt.Errorf("%s exists but is not a valid git repository, remove it manually to re-clone: %w", path, err)
		}
		err = withCloneRetries(ctx, func() error { return fetchRepo(ctx, userInfo, gitURL, path, timeout) })
	case os.IsNotExist(statErr):
		err = withCloneRetries(ctx, func() error { return cloneToPersistentPath(ctx, userInfo, gitURL, path, timeout) })
	default:
		return "", nil, fmt.Errorf("could not access clone path %s: %w", path, statErr)
	}
	if err != nil {
		return "", nil, err
	}

	repo, err := RepoFromPath(path)
	if err != nil {
		return "", nil, fmt.Errorf("could not open repo: %w", err)
	}
	return path, repo, nil
}

// CloneOrFetchRepoUsingToken is CloneOrFetchRepo with token authentication.
func CloneOrFetchRepoUsingToken(ctx context.Context, token, gitURL, clonePath, user string) (string, *git.Repository, error) {
	return CloneOrFetchRepo(ctx, url.UserPassword(user, token), gitURL, clonePath)
}

// CloneOrFetchRepoUsingUnauthenticated is CloneOrFetchRepo without authentication.
func CloneOrFetchRepoUsingUnauthenticated(ctx context.Context, gitURL, clonePath string) (string, *git.Repository, error) {
	return CloneOrFetchRepo(ctx, nil, gitURL, clonePath)
}

// cloneToPersistentPath clones into <path>.partial and renames it into place on success, so an interrupted clone never
// looks like a valid repository.
func cloneToPersistentPath(ctx context.Context, userInfo *url.Userinfo, gitURL, path string, timeout time.Duration) error {
	partial := path + partialCloneSuffix
	// Only ever an incomplete clone from an earlier attempt.
	if err := os.RemoveAll(partial); err != nil {
		return fmt.Errorf("could not remove incomplete clone %s: %w", partial, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("could not create clone directory: %w", err)
	}

	if _, err := executeClone(ctx, cloneParams{userInfo: userInfo, gitURL: gitURL, clonePath: partial, authInUrl: false, timeout: timeout}); err != nil {
		_ = os.RemoveAll(partial)
		return err
	}
	if err := os.Rename(partial, path); err != nil {
		return fmt.Errorf("could not move clone into place: %w", err)
	}
	return nil
}

// fetchRepo fetches into an existing clone using the refspec it was cloned with. It never prunes.
func fetchRepo(ctx context.Context, userInfo *url.Userinfo, gitURL, path string, timeout time.Duration) error {
	expected, err := GitURLParse(gitURL)
	if err != nil {
		return fmt.Errorf("could not parse clone url: %w", err)
	}
	expected.User = nil

	if err := verifyOrigin(ctx, path, expected); err != nil {
		return err
	}
	if err := preserveRefs(ctx, path); err != nil {
		return fmt.Errorf("could not preserve existing refs: %w", err)
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	secret, _ := userInfo.Password()
	cmd := exec.CommandContext(ctx, "git", fetchArgs(userInfo, expected, path)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)
	if secret != "" {
		output = strings.ReplaceAll(output, secret, "<secret>")
	}
	if common.IsDone(ctx) {
		return fmt.Errorf("git fetch timed out or was cancelled: %w", ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("error executing git fetch: %w, %s", err, output)
	}
	return nil
}

// fetchArgs builds the git arguments for a fetch. Credentials are limited to requests for remote, so they are never
// sent to any other URL the clone's configuration might point at.
func fetchArgs(userInfo *url.Userinfo, remote *url.URL, path string) []string {
	var args []string
	if pass, ok := userInfo.Password(); ok {
		header := base64.StdEncoding.EncodeToString([]byte(userInfo.Username() + ":" + pass))
		args = append(args, "-c", "http."+remote.String()+".extraHeader=Authorization: Basic "+header)
	}
	return append(args, "-C", path, "fetch", "--quiet", "--no-prune", "--force", "--tags", "origin")
}

// verifyOrigin fails unless the clone's effective origin URL (after any insteadOf rewriting) is the expected repository.
func verifyOrigin(ctx context.Context, path string, expected *url.URL) error {
	out, err := gitOutput(ctx, path, "", "ls-remote", "--get-url", "origin")
	if err != nil {
		return err
	}
	// The URL itself is left out of the error since a hand-edited origin may embed credentials.
	actual, err := GitURLParse(strings.TrimSpace(out))
	if err != nil || !sameRemote(actual, expected) {
		return fmt.Errorf("origin of %s is not the expected repository, refusing to fetch", path)
	}
	return nil
}

// sameRemote reports whether a and b name the same repository over the same scheme.
func sameRemote(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	pathA, errA := PersistentClonePath(withoutUser(a), "")
	pathB, errB := PersistentClonePath(withoutUser(b), "")
	return errA == nil && errB == nil && pathA == pathB
}

func withoutUser(u *url.URL) string {
	c := *u
	c.User = nil
	return c.String()
}

// preserveRefs creates refs/trufflehog/preserved/<sha> for every ref tip not already preserved, so overwriting a ref
// during a forced fetch can't leave its old commits unreachable (and therefore collectable by git's own gc).
func preserveRefs(ctx context.Context, path string) error {
	out, err := gitOutput(ctx, path, "", "for-each-ref", "--format=%(objectname) %(refname)")
	if err != nil {
		return err
	}

	preserved := map[string]struct{}{}
	var tips []string
	for _, line := range strings.Split(out, "\n") {
		sha, name, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(name, preservedRefPrefix):
			preserved[sha] = struct{}{}
		case strings.HasPrefix(name, trufflehogRefPrefix):
		default:
			tips = append(tips, sha)
		}
	}

	var commands strings.Builder
	created := 0
	for _, sha := range tips {
		if _, ok := preserved[sha]; ok {
			continue
		}
		preserved[sha] = struct{}{}
		fmt.Fprintf(&commands, "create %s%s %s\n", preservedRefPrefix, sha, sha)
		created++
	}
	if created == 0 {
		return nil
	}

	if _, err := gitOutput(ctx, path, commands.String(), "update-ref", "--stdin"); err != nil {
		return err
	}
	if created >= packRefsThreshold {
		// Keeps thousands of preserved refs from becoming thousands of loose files; removes nothing.
		if _, err := gitOutput(ctx, path, "", "pack-refs", "--all"); err != nil {
			ctx.Logger().V(1).Info("could not pack refs", "error", err.Error())
		}
	}
	return nil
}

// RefsDigest returns a digest of every ref and the object it points to, ignoring trufflehog's own refs.
func RefsDigest(ctx context.Context, path string) (string, error) {
	out, err := gitOutput(ctx, path, "", "for-each-ref", "--format=%(refname) %(objectname)")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, trufflehogRefPrefix) {
			continue
		}
		h.Write([]byte(line + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ScannedRefsDigest returns the refs digest recorded by the last successful scan, or "" if there is none.
func ScannedRefsDigest(ctx context.Context, path string) string {
	out, err := gitOutput(ctx, path, "", "config", "--local", "--get", scannedRefsDigestKey)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// SetScannedRefsDigest records the refs digest of a successfully scanned clone in its own git config.
func SetScannedRefsDigest(ctx context.Context, path, digest string) error {
	_, err := gitOutput(ctx, path, "", "config", "--local", scannedRefsDigestKey, digest)
	return err
}

func gitOutput(ctx context.Context, dir, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s failed: %w, %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// withCloneRetries runs op, retrying transient network and rate-limit failures like CloneRepo does.
func withCloneRetries(ctx context.Context, op func() error) error {
	var err error
	for attempt := 1; attempt <= maxCloneAttempts; attempt++ {
		if err = op(); err == nil {
			return nil
		}
		if attempt >= maxCloneAttempts || !isRetryableCloneError(err) || common.IsDone(ctx) {
			return err
		}

		delay := cloneRetryDelay(err, attempt)
		ctx.Logger().Info("git operation interrupted; retrying",
			"attempt", attempt,
			"max_attempts", maxCloneAttempts,
			"delay", delay.String(),
			"error", err.Error(),
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}
