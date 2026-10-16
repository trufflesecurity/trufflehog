package giturl

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// Pins GenerateLink output for file names without control characters across providers.
func TestCharacterizeGenerateLinkWithoutControlChars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		repo string
		file string
		line int64
		want string
	}{
		{name: "github literal percent-0D file name", repo: "https://github.com/org/repo.git", file: "a%0Db", line: 1, want: "https://github.com/org/repo/blob/abc123/a%250Db#L1"},
		{name: "github literal percent-7F file name", repo: "https://github.com/org/repo.git", file: "a%7fb", line: 1, want: "https://github.com/org/repo/blob/abc123/a%257fb#L1"},
		{name: "github percent and brackets", repo: "https://github.com/org/repo.git", file: "a%b[c]", line: 1, want: "https://github.com/org/repo/blob/abc123/a%25b%5Bc%5D#L1"},
		{name: "github space hash question unicode", repo: "https://github.com/org/repo.git", file: "dir/a b#c?d+é.go", line: 2, want: "https://github.com/org/repo/blob/abc123/dir/a b#c?d+é.go#L2"},
		{name: "github no line", repo: "https://github.com/org/repo.git", file: "dir/a%b.go", line: 0, want: "https://github.com/org/repo/blob/abc123/dir/a%25b.go"},
		{name: "gitlab percent", repo: "https://gitlab.com/org/repo.git", file: "a%b[c].go", line: 3, want: "https://gitlab.com/org/repo/blob/abc123/a%25b%5Bc%5D.go#L3"},
		{name: "bitbucket percent and brackets", repo: "https://bitbucket.org/org/repo.git", file: "a%b[c].go", line: 4, want: "https://bitbucket.org/org/repo/src/abc123/a%25b%5Bc%5D.go#lines-4"},
		{name: "azure percent and brackets", repo: "https://dev.azure.com/org/project/_git/repo", file: "a%b[c].go", line: 5, want: "https://dev.azure.com/org/project/_git/repo?path=/a%25b%5Bc%5D.go&version=GCabc123&line=5&lineEnd=6&lineStartColumn=1"},
		{name: "gist percent and brackets", repo: "https://gist.github.com/user/abc123.git", file: "a%b[c].go", line: 6, want: "https://gist.github.com/user/abc123/abc123/#file-a%25b%5Bc%5D-go-L6"},
		{name: "wiki percent and brackets", repo: "https://github.com/org/repo.wiki.git", file: "a%b[c].md", line: 7, want: "https://github.com/org/repo/wiki/a%25b%5Bc%5D/abc123#L7"},
		{name: "github empty file", repo: "https://github.com/org/repo.git", file: "", line: 1, want: "https://github.com/org/repo/commit/abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenerateLink(tt.repo, "abc123", tt.file, tt.line); got != tt.want {
				t.Errorf("GenerateLink() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Pins UpdateLinkLineNumber output for links without control-character escapes,
// and the failure path for links holding raw control bytes.
func TestCharacterizeUpdateLinkLineNumberWithoutControlChars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		link    string
		newLine int64
		want    string
	}{
		{name: "non-control escape is double-encoded", link: "https://github.com/org/repo/blob/abc123/a%20b#L1", newLine: 4, want: "https://github.com/org/repo/blob/abc123/a%2520b#L4"},
		{name: "lowercase non-control escape is double-encoded", link: "https://github.com/org/repo/blob/abc123/a%2fb#L1", newLine: 4, want: "https://github.com/org/repo/blob/abc123/a%252fb#L4"},
		{name: "escape starting with 2 is double-encoded", link: "https://github.com/org/repo/blob/abc123/a%2Db#L1", newLine: 4, want: "https://github.com/org/repo/blob/abc123/a%252Db#L4"},
		{name: "escape starting with 7 but not 7F is double-encoded", link: "https://github.com/org/repo/blob/abc123/a%7Eb#L1", newLine: 4, want: "https://github.com/org/repo/blob/abc123/a%257Eb#L4"},
		{name: "trailing bare percent", link: "https://github.com/org/repo/blob/abc123/a%", newLine: 4, want: "https://github.com/org/repo/blob/abc123/a%25#L4"},
		{name: "percent followed by one hex digit", link: "https://github.com/org/repo/blob/abc123/a%1", newLine: 4, want: "https://github.com/org/repo/blob/abc123/a%251#L4"},
		{name: "zero line returns replaced string", link: "https://github.com/org/repo/blob/abc123/a%20b[c]#L1", newLine: 0, want: "https://github.com/org/repo/blob/abc123/a%2520b%5Bc%5D#L1"},
		{name: "negative line returns replaced string", link: "https://github.com/org/repo/blob/abc123/a%b#L1", newLine: -1, want: "https://github.com/org/repo/blob/abc123/a%25b#L1"},
		{name: "raw control byte fails and returns replaced string", link: "https://github.com/org/repo/blob/abc123/a%b\rc#L1", newLine: 9, want: "https://github.com/org/repo/blob/abc123/a%25b\rc#L1"},
		{name: "raw tab fails and returns replaced string", link: "https://github.com/org/repo/blob/abc123/a[b]\tc#L1", newLine: 9, want: "https://github.com/org/repo/blob/abc123/a%5Bb%5D\tc#L1"},
		{name: "bitbucket percent", link: "https://bitbucket.org/org/repo/src/abc123/a%25b.go#lines-1", newLine: 8, want: "https://bitbucket.org/org/repo/src/abc123/a%2525b.go#lines-8"},
		{name: "azure percent in path query", link: "https://dev.azure.com/org/project/_git/repo?path=/a%25b%5Bc%5D.go&version=GCabc123&line=1&lineEnd=2&lineStartColumn=1", newLine: 8, want: "https://dev.azure.com/org/project/_git/repo?line=8&lineEnd=9&lineStartColumn=1&path=%2Fa%2525b%255Bc%255D.go&version=GCabc123"},
		{name: "gist percent in fragment", link: "https://gist.github.com/user/abc123/#file-a%25b-go-L1", newLine: 8, want: "https://gist.github.com/user/abc123/#file-a%2525b-go-L8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UpdateLinkLineNumber(context.Background(), tt.link, tt.newLine); got != tt.want {
				t.Errorf("UpdateLinkLineNumber() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Pins the GenerateLink -> UpdateLinkLineNumber round trip for file names without control characters.
func TestCharacterizeGenerateLinkThenUpdateWithoutControlChars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		repo    string
		file    string
		newLine int64
		want    string
	}{
		{name: "github literal percent-0D file name", repo: "https://github.com/org/repo.git", file: "a%0Db", newLine: 5, want: "https://github.com/org/repo/blob/abc123/a%25250Db#L5"},
		{name: "github literal lowercase percent-1f file name", repo: "https://github.com/org/repo.git", file: "a%1fb", newLine: 5, want: "https://github.com/org/repo/blob/abc123/a%25251fb#L5"},
		{name: "github literal percent-7F file name", repo: "https://github.com/org/repo.git", file: "a%7Fb", newLine: 5, want: "https://github.com/org/repo/blob/abc123/a%25257Fb#L5"},
		{name: "github percent and brackets", repo: "https://github.com/org/repo.git", file: "a%b[c]", newLine: 5, want: "https://github.com/org/repo/blob/abc123/a%2525b%255Bc%255D#L5"},
		{name: "github space and unicode", repo: "https://github.com/org/repo.git", file: "dir/a b é.go", newLine: 5, want: "https://github.com/org/repo/blob/abc123/dir/a%20b%20%C3%A9.go#L5"},
		{name: "gitlab percent", repo: "https://gitlab.com/org/repo.git", file: "a%b.go", newLine: 5, want: "https://gitlab.com/org/repo/blob/abc123/a%2525b.go#L5"},
		{name: "bitbucket percent and brackets", repo: "https://bitbucket.org/org/repo.git", file: "a%b[c].go", newLine: 5, want: "https://bitbucket.org/org/repo/src/abc123/a%2525b%255Bc%255D.go#lines-5"},
		{name: "azure percent and brackets", repo: "https://dev.azure.com/org/project/_git/repo", file: "a%b[c].go", newLine: 5, want: "https://dev.azure.com/org/project/_git/repo?line=5&lineEnd=6&lineStartColumn=1&path=%2Fa%2525b%255Bc%255D.go&version=GCabc123"},
		{name: "gist percent and brackets", repo: "https://gist.github.com/user/abc123.git", file: "a%b[c].go", newLine: 5, want: "https://gist.github.com/user/abc123/abc123/#file-a%2525b%255Bc%255D-go-L5"},
		{name: "wiki percent and brackets", repo: "https://github.com/org/repo.wiki.git", file: "a%b[c].md", newLine: 5, want: "https://github.com/org/repo/wiki/a%2525b%255Bc%255D/abc123#L5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := GenerateLink(tt.repo, "abc123", tt.file, 1)
			if got := UpdateLinkLineNumber(context.Background(), link, tt.newLine); got != tt.want {
				t.Errorf("round trip = %q, want %q", got, tt.want)
			}
		})
	}
}
