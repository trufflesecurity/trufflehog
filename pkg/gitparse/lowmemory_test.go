package gitparse

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// The lower-memory scan splits one `git log` into a `git rev-list` that lists commits
// and a `git log` per group that generates their patches. These tests hold it to the
// only thing that really matters: it must find exactly what the single-command form
// finds, wherever the group boundaries happen to land.

// collectDiffs drains a diff channel into something comparable. Content is included,
// since a group boundary in the wrong place could keep the commit and lose its patch.
func collectDiffs(t *testing.T, diffChan chan *Diff) []string {
	t.Helper()

	var out []string
	for diff := range diffChan {
		content := ""
		// A commit with no diffs arrives with nothing written, and asking such a diff
		// for its content fails, so check before reading.
		if diff.contentWriter != nil && diff.Len() > 0 {
			got, err := diff.contentWriter.String()
			if err != nil {
				t.Fatalf("reading diff content: %v", err)
			}
			content = got
		}
		out = append(out, strings.Join([]string{diff.Commit.Hash, diff.PathB, content}, "\x00"))
	}
	return out
}

func TestLowMemoryScanMatchesSingleProcess(t *testing.T) {
	repo := testRepoRoot(t)

	// abbreviatedLog is the caller's BaseHash == "", so both values are real
	// configurations and they take different paths through git. With it on, git drops
	// commits whose diffs are all filtered away; with it off, those commits stay.
	//
	// The group sizes go down to 1 on purpose. Every group ends a stream, and a commit
	// with no diffs used to be dropped when it landed at the end of one, so a size of 1
	// puts every commit in that spot at once. Before cleanupParse learned to finish off
	// the last commit, this repository lost 84 diffs at size 1 and 1 at size 75.
	for _, tc := range []struct {
		name        string
		abbreviated bool
	}{
		{"abbreviated", true},
		{"full", false},
	} {
		abbreviated, name := tc.abbreviated, tc.name

		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			single := NewParser()
			singleChan, err := single.RepoPath(ctx, repo, "", abbreviated, nil, false)
			if err != nil {
				t.Fatalf("single-process RepoPath: %v", err)
			}
			want := collectDiffs(t, singleChan)
			if len(want) == 0 {
				t.Fatal("single-process scan produced no diffs")
			}

			// Group sizes small enough that this repository crosses boundaries, which
			// is the only place the two forms can drift apart.
			for _, groupSize := range []int{1, 2, 7, 500} {
				low := NewParser(UseLowMemoryScan())
				low.groupSize = groupSize

				lowChan, err := low.RepoPath(ctx, repo, "", abbreviated, nil, false)
				if err != nil {
					t.Fatalf("group size %d: RepoPath: %v", groupSize, err)
				}
				got := collectDiffs(t, lowChan)

				if len(got) != len(want) {
					t.Fatalf("group size %d: got %d diffs, want %d", groupSize, len(got), len(want))
				}
				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("group size %d: diff %d differs\n got: %q\nwant: %q",
							groupSize, i, got[i], want[i])
					}
				}
			}
		})
	}
}

// TestLowMemoryScanExcludedGlobs checks the path filters reach both commands. They
// decide which commits rev-list lists and which files the patches contain, so sending
// them to only one of the two would quietly change what gets scanned.
func TestLowMemoryScanExcludedGlobs(t *testing.T) {
	repo := testRepoRoot(t)
	ctx := context.Background()
	globs := []string{"*.go"}

	single := NewParser()
	singleChan, err := single.RepoPath(ctx, repo, "", true, globs, false)
	if err != nil {
		t.Fatalf("single-process RepoPath: %v", err)
	}
	want := collectDiffs(t, singleChan)

	low := NewParser(UseLowMemoryScan())
	low.groupSize = 13
	lowChan, err := low.RepoPath(ctx, repo, "", true, globs, false)
	if err != nil {
		t.Fatalf("low-memory RepoPath: %v", err)
	}
	got := collectDiffs(t, lowChan)

	if len(got) != len(want) {
		t.Fatalf("got %d diffs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("diff %d differs\n got: %q\nwant: %q", i, got[i], want[i])
		}
	}
}

// TestLowMemoryScanUnknownHead covers the error the old form threw away. A bad revision
// used to be logged and the channel closed, so a typo in a branch name looked exactly
// like an empty repository.
func TestLowMemoryScanUnknownHead(t *testing.T) {
	repo := testRepoRoot(t)

	parser := NewParser(UseLowMemoryScan())
	if _, err := parser.RepoPath(context.Background(), repo, "no-such-ref-exists", true, nil, false); err == nil {
		t.Fatal("expected an error for an unknown head, got nil")
	}
}

// TestLowMemoryScanEmptyRepo checks a repository with no commits ends the scan cleanly
// rather than failing. rev-list prints nothing and exits zero, which has to be told
// apart from rev-list printing nothing because it failed.
func TestLowMemoryScanEmptyRepo(t *testing.T) {
	dir := t.TempDir()
	runTestGit(t, dir, "init", "-q")

	parser := NewParser(UseLowMemoryScan())
	diffChan, err := parser.RepoPath(context.Background(), dir, "", true, nil, false)
	if err != nil {
		t.Fatalf("RepoPath on an empty repo: %v", err)
	}
	if n := len(collectDiffs(t, diffChan)); n != 0 {
		t.Fatalf("got %d diffs from an empty repo, want 0", n)
	}
}

// TestLowMemoryScanAbandonedByConsumer covers a caller that stops reading early, which
// is what a depth-limited scan does. Reading one diff and walking away must not leave
// the scan wedged; the cancel in ScanCommits is what releases it in production, so the
// same cancel stands in for it here.
func TestLowMemoryScanAbandonedByConsumer(t *testing.T) {
	repo := testRepoRoot(t)
	ctx, cancel := context.WithCancel(context.Background())

	parser := NewParser(UseLowMemoryScan())
	parser.groupSize = 2

	diffChan, err := parser.RepoPath(ctx, repo, "", true, nil, false)
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}

	// Take a single diff, then stop, the way the scan loop does at max depth.
	if _, ok := <-diffChan; !ok {
		t.Fatal("expected at least one diff")
	}
	cancel()

	// Draining to the end must finish. If it hangs the test times out, which is the
	// failure we are looking for.
	for range diffChan { //nolint:revive // draining
	}
}

func TestCommitGroupSize(t *testing.T) {
	// A size of zero or less would mean a group that never fills, so it falls back.
	for _, tc := range []struct{ set, want int }{
		{0, logGroupSize},
		{-1, logGroupSize},
		{1, 1},
		{99, 99},
	} {
		parser := NewParser()
		parser.groupSize = tc.set
		if got := parser.commitGroupSize(); got != tc.want {
			t.Errorf("groupSize %d: got %d, want %d", tc.set, got, tc.want)
		}
	}
}

// testRepoRoot returns the root of the git checkout the tests run from. The real
// history has the merges, binaries, renames and uneven commit sizes that a hand-built
// fixture does not, which is where a batching mistake actually shows up.
func testRepoRoot(tb testing.TB) string {
	tb.Helper()

	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		tb.Skip("not running from a git checkout")
	}
	root := strings.TrimSpace(string(out))
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		tb.Skip("no .git directory")
	}
	return root
}

func runTestGit(tb testing.TB, dir string, args ...string) {
	tb.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// TestTrailingCommitWithoutDiffsIsReported pins down the rule that a commit is finished
// off at the end of a stream, not only when the next commit line arrives.
//
// A commit with no diffs of its own still carries a message, an author and notes, and
// those are worth scanning. The main loop has always sent such a commit on when it saw
// the next one start, but the end of the stream had no equivalent, so whichever commit
// happened to be last was dropped. One `git log` for a whole repository made that nearly
// harmless, since only the oldest commit in the history was ever in that spot. Splitting
// the log into groups puts a different commit there for every group.
func TestTrailingCommitWithoutDiffsIsReported(t *testing.T) {
	dir := t.TempDir()
	runTestGit(t, dir, "init", "-q")
	runTestGit(t, dir, "config", "user.email", "test@example.com")
	runTestGit(t, dir, "config", "user.name", "Test")

	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, dir, "add", "-A")
	runTestGit(t, dir, "commit", "-qm", "adds a file")

	// An empty commit has a message but changes nothing, which is the shape that used
	// to disappear.
	runTestGit(t, dir, "commit", "-q", "--allow-empty", "-m", "empty commit worth scanning")

	// Group size 1 puts the empty commit at the end of its own stream, which is exactly
	// where it used to be lost.
	parser := NewParser(UseLowMemoryScan())
	parser.groupSize = 1

	diffChan, err := parser.RepoPath(context.Background(), dir, "", false, nil, false)
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}

	var messages []string
	for diff := range diffChan {
		messages = append(messages, diff.Commit.Message.String())
	}

	var found bool
	for _, msg := range messages {
		if strings.Contains(msg, "empty commit worth scanning") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the empty commit was never reported; got %d diffs with messages %q", len(messages), messages)
	}
}
