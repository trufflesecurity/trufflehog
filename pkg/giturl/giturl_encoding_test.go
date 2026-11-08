package giturl

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// TestGenerateLinkEncodingSurvivesLineUpdates exercises the finding link pipeline.
func TestGenerateLinkEncodingSurvivesLineUpdates(t *testing.T) {
	t.Parallel()
	files := []struct {
		name, file, escaped string
	}{
		{"carriage return", "\rexit", "%0Dexit"},
		{"newline", "dir/line\nbreak.txt", "dir/line%0Abreak.txt"},
		{"tab", "dir/tab\tname.txt", "dir/tab%09name.txt"},
		{"delete", "dir/delete\x7f.txt", "dir/delete%7F.txt"},
		{"literal escape", "dir/%0Dexit", "dir/%250Dexit"},
		{"brackets and percent", "dir/[100%]/file.txt", "dir/%5B100%25%5D/file.txt"},
		{"reserved characters", "dir/file #1?.txt", "dir/file%20%231%3F.txt"},
	}
	providers := []struct {
		name, repo, prefix, fragment string
	}{
		{"github", "https://github.com/org/repo.git", "https://github.com/org/repo/blob/abc123/", "L"},
		{"gitlab", "https://gitlab.com/org/repo.git", "https://gitlab.com/org/repo/blob/abc123/", "L"},
		{"bitbucket", "https://bitbucket.org/org/repo.git", "https://bitbucket.org/org/repo/src/abc123/", "lines-"},
		{"on-prem", "https://git.example.com/org/repo.git", "https://git.example.com/org/repo/blob/abc123/", "L"},
	}
	for _, provider := range providers {
		for _, file := range files {
			t.Run(provider.name+"/"+file.name, func(t *testing.T) {
				link := GenerateLink(provider.repo, "abc123", file.file, 1)
				want := provider.prefix + file.escaped + "#" + provider.fragment + "1"
				if link != want {
					t.Fatalf("GenerateLink() = %q, want %q", link, want)
				}
				if got := UpdateLinkLineNumber(context.Background(), link, 0); got != want {
					t.Fatalf("zero-line update = %q, want unchanged %q", got, want)
				}
				link = UpdateLinkLineNumber(context.Background(), link, 7)
				want = provider.prefix + file.escaped + "#" + provider.fragment + "7"
				if link != want {
					t.Fatalf("line update = %q, want %q", link, want)
				}
				if got := UpdateLinkLineNumber(context.Background(), link, 7); got != want {
					t.Fatalf("repeated line update = %q, want %q", got, want)
				}
			})
		}
	}
}

// TestUpdateLinkLineNumberPreservesEscapes covers valid and malformed percent escapes.
func TestUpdateLinkLineNumberPreservesEscapes(t *testing.T) {
	t.Parallel()
	tests := []struct{ file, want string }{
		{"%0Dexit", "%0Dexit"},
		{"%0dexit", "%0dexit"},
		{"%250Dexit", "%250Dexit"},
		{"%0D/100%/file", "%0D/100%25/file"},
		{"file%2", "file%252"},
		{"file%zz", "file%25zz"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			prefix := "https://github.com/org/repo/blob/abc123/"
			got := UpdateLinkLineNumber(context.Background(), prefix+tt.file+"#L1", 7)
			if want := prefix + tt.want + "#L7"; got != want {
				t.Errorf("UpdateLinkLineNumber() = %q, want %q", got, want)
			}
		})
	}
}
