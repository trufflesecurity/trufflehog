package gitparse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// A renamed file must reach the scanner at its new path. trufflehog runs its
// full-history scans with rename detection on (git's default) and
// --diff-filter=AM, and the R status is not in that filter, so `git log`
// reports nothing at all for the commit that only renamed a file: content
// that is still live in the repository, under the new name, is never scanned
// (#4672). This test scans a history whose second commit only renames the
// file and requires a diff carrying the content at the new path.
func TestRenamedFileIsScannedAtNewPath(t *testing.T) {
	dir := t.TempDir()
	runTestGit(t, dir, "init", "-q")
	runTestGit(t, dir, "config", "user.email", "test@example.com")
	runTestGit(t, dir, "config", "user.name", "Test")

	content := "first line\nmarker-for-rename-test\nlast line\n"
	if err := os.WriteFile(filepath.Join(dir, "before.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, dir, "add", "-A")
	runTestGit(t, dir, "commit", "-qm", "adds a file")

	runTestGit(t, dir, "mv", "before.txt", "after.txt")
	runTestGit(t, dir, "commit", "-qm", "renames the file")

	for name, parser := range map[string]*Parser{
		"single command": NewParser(),
		"low memory":     NewParser(UseLowMemoryScan()),
	} {
		t.Run(name, func(t *testing.T) {
			diffChan, err := parser.RepoPath(context.Background(), dir, "", "", nil, false)
			if err != nil {
				t.Fatalf("RepoPath: %v", err)
			}

			found := map[string]bool{}
			for diff := range diffChan {
				if diff.Len() == 0 {
					continue
				}
				got, err := diff.contentWriter.String()
				if err != nil {
					t.Fatalf("reading diff for %s: %v", diff.PathB, err)
				}
				if strings.Contains(got, "marker-for-rename-test") {
					found[diff.PathB] = true
				}
			}

			if !found["before.txt"] {
				t.Errorf("content was not scanned at the original path; got paths %v", found)
			}
			if !found["after.txt"] {
				t.Errorf("renamed file was not scanned at its new path; got paths %v", found)
			}
		})
	}
}

// The staged scan runs the same rename detection plus --diff-filter=AM
// combination through `git diff --cached`, so a rename that exists only in
// the index is dropped the same way a committed one is: `git diff` reports
// nothing at all for it, and live content under the new name is never
// scanned (#4672). This test stages (but does not commit) a rename and
// requires a diff carrying the content at the new path.
func TestStagedRenameIsScannedAtNewPath(t *testing.T) {
	dir := t.TempDir()
	runTestGit(t, dir, "init", "-q")
	runTestGit(t, dir, "config", "user.email", "test@example.com")
	runTestGit(t, dir, "config", "user.name", "Test")

	content := "first line\nmarker-for-staged-rename-test\nlast line\n"
	if err := os.WriteFile(filepath.Join(dir, "before.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, dir, "add", "-A")
	runTestGit(t, dir, "commit", "-qm", "adds a file")

	// Stage the rename only; HEAD still names the file before.txt.
	runTestGit(t, dir, "mv", "before.txt", "after.txt")

	diffChan, err := NewParser().Staged(context.Background(), dir)
	if err != nil {
		t.Fatalf("Staged: %v", err)
	}

	found := false
	for diff := range diffChan {
		if diff.Len() == 0 {
			continue
		}
		got, err := diff.contentWriter.String()
		if err != nil {
			t.Fatalf("reading diff for %s: %v", diff.PathB, err)
		}
		if diff.PathB == "after.txt" && strings.Contains(got, "marker-for-staged-rename-test") {
			found = true
		}
	}

	if !found {
		t.Errorf("staged rename was not scanned at its new path")
	}
}
