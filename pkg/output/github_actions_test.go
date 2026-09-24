package output

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

// gitResultWithFile builds a verified git-family result whose file path is caller-controlled,
// mirroring a path decoded by pkg/gitparse that can contain characters git allows in paths,
// such as a newline.
func gitResultWithFile(file string) *detectors.ResultWithMetadata {
	return &detectors.ResultWithMetadata{
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Git{
				Git: &source_metadatapb.Git{File: file, Line: 1},
			},
		},
		SourceType: sourcespb.SourceType_SOURCE_TYPE_GIT,
		SourceName: "my-repo",
		Result: detectors.Result{
			DetectorType: detector_typepb.DetectorType_Github,
			Raw:          []byte("secret"),
			Verified:     false,
		},
	}
}

func TestEscapeWorkflowData(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "config/prod.yaml", "config/prod.yaml"},
		{"newline is escaped", "a\nb", "a%0Ab"},
		{"carriage return is escaped", "a\rb", "a%0Db"},
		{"percent is escaped first so it can't unmask other sequences", "100%\n", "100%25%0A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, escapeWorkflowData(tt.in))
		})
	}
}

func TestEscapeWorkflowProperty(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "config/prod.yaml", "config/prod.yaml"},
		{"colon is escaped", "a:b", "a%3Ab"},
		{"comma is escaped", "a,b", "a%2Cb"},
		{"newline is escaped, same as data", "a\nb", "a%0Ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, escapeWorkflowProperty(tt.in))
		})
	}
}

// TestFormatWarningCommand_EscapesSpecialCharactersInFilename covers a file path containing
// characters git allows but the workflow-command syntax does not: git permits newlines in file
// paths, and gitparse decodes the git-quoted diff-header form back into a real newline (see
// pkg/gitparse pathFromToFileLine). Unescaped, an embedded newline followed by "::" would start
// what looks like a second workflow command on its own line.
func TestFormatWarningCommand_EscapesSpecialCharactersInFilename(t *testing.T) {
	unusualFile := "readme.md\n::error title=example::some text\n::add-mask::some-value"

	got := formatWarningCommand(unusualFile, 1, "Found unverified result\n")

	require.Equal(t, 1, strings.Count(got, "\n"), "output must be exactly one line (plus its trailing newline)")
	assert.NotContains(t, got, "\n::error", "no unescaped newline should start a new line")
	assert.NotContains(t, got, "\n::add-mask", "no unescaped newline should start a new line")
	assert.Contains(t, got, "%0A", "the embedded newlines must survive, escaped, rather than being silently dropped")
	assert.True(t, strings.HasPrefix(got, "::warning file="), "the tool's own command must still be well-formed")
}

func TestGitHubActionsPrinter_Print_HandlesFilenameWithSpecialCharacters(t *testing.T) {
	dedupeCache = make(map[string]struct{}) // isolate from other tests sharing the package-level cache

	p := &GitHubActionsPrinter{}
	unusualFile := "readme.md\n::stop-commands::deadbeef"

	require.NoError(t, p.Print(context.Background(), gitResultWithFile(unusualFile)))
}
