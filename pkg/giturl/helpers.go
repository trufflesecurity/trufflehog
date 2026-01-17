package giturl

import (
	"path/filepath"
	"strings"
)

// TrimGitSuffix removes the .git suffix from a repository URL.
func TrimGitSuffix(repo string) string {
	return strings.TrimSuffix(repo, ".git")
}

// EncodeSpecialChars encodes special characters in file paths that would
// break URL parsing. Specifically handles %, [, and ].
func EncodeSpecialChars(path string) string {
	path = strings.ReplaceAll(path, "%", "%25")
	path = strings.ReplaceAll(path, "[", "%5B")
	path = strings.ReplaceAll(path, "]", "%5D")
	return path
}

// IsGistURL returns true if the repository URL is a GitHub gist.
func IsGistURL(repo string) bool {
	return strings.Contains(repo, "gist.github.com")
}

// IsWikiURL returns true if the repository URL is a GitHub wiki.
func IsWikiURL(repo string) bool {
	return strings.HasSuffix(repo, ".wiki.git")
}

// TrimWikiSuffix removes the .wiki.git suffix from a repository URL.
func TrimWikiSuffix(repo string) string {
	return strings.TrimSuffix(repo, ".wiki.git")
}

// CleanGistFilename converts a filename to the format used in gist URLs.
// Dots in filenames are replaced with hyphens.
func CleanGistFilename(filename string) string {
	return strings.ReplaceAll(filename, ".", "-")
}

// TrimFileExtension removes the file extension from a path.
func TrimFileExtension(path string) string {
	return strings.TrimSuffix(path, filepath.Ext(path))
}
