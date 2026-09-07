package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestObjectFilter(t *testing.T, includePrefixes, excludePrefixes, includeExts, excludeExts []string) *objectFilter {
	t.Helper()

	filter, err := newObjectFilter(includePrefixes, excludePrefixes, includeExts, excludeExts)
	require.NoError(t, err)
	return filter
}

func TestObjectFilter_Unconfigured(t *testing.T) {
	filter := newTestObjectFilter(t, nil, nil, nil, nil)

	assert.True(t, filter.shouldInclude("any/key.zip"))
	assert.True(t, filter.shouldInclude("Makefile"))
	assert.True(t, (*objectFilter)(nil).shouldInclude("any/key.zip"))
}

func TestObjectFilter_ExcludePrefix(t *testing.T) {
	filter := newTestObjectFilter(t, nil, []string{"projects/abc/"}, nil, nil)

	assert.False(t, filter.shouldInclude("projects/abc/config.yaml"))
	assert.True(t, filter.shouldInclude("projects/xyz/config.yaml"))
}

func TestObjectFilter_IncludePrefix(t *testing.T) {
	filter := newTestObjectFilter(t, []string{"infra/"}, nil, nil, nil)

	assert.True(t, filter.shouldInclude("infra/main.tf"))
	assert.False(t, filter.shouldInclude("media/clip.mp4"))

	// A prefix is matched literally, so it is not confined to a path boundary.
	assert.True(t, newTestObjectFilter(t, []string{"log"}, nil, nil, nil).shouldInclude("logs-archive/app.txt"))
}

func TestObjectFilter_IncludeAndExcludePrefixes(t *testing.T) {
	filter := newTestObjectFilter(t, []string{"src/"}, []string{"src/vendor/"}, nil, nil)

	assert.True(t, filter.shouldInclude("src/main.go"))
	assert.False(t, filter.shouldInclude("src/vendor/dep.go"), "exclusion takes precedence")
	assert.False(t, filter.shouldInclude("docs/readme.md"), "matches no include prefix")
}

func TestObjectFilter_ExcludeExtension(t *testing.T) {
	filter := newTestObjectFilter(t, nil, nil, nil, []string{"zip", ".MP4"})

	assert.False(t, filter.shouldInclude("build/artifact.zip"))
	assert.False(t, filter.shouldInclude("build/ARTIFACT.ZIP"), "matching is case insensitive")
	assert.False(t, filter.shouldInclude("media/clip.mp4"), "a configured leading dot is tolerated")
	assert.True(t, filter.shouldInclude("infra/main.tf"))
	assert.True(t, filter.shouldInclude("Makefile"), "a key with no extension is not excluded")
}

func TestObjectFilter_IncludeExtension(t *testing.T) {
	filter := newTestObjectFilter(t, nil, nil, []string{"tf", "yaml"}, nil)

	assert.True(t, filter.shouldInclude("infra/main.tf"))
	assert.True(t, filter.shouldInclude("infra/vars.yaml"))
	assert.False(t, filter.shouldInclude("infra/state.json"))
	assert.False(t, filter.shouldInclude("Makefile"), "a key with no extension matches no entry")
}

func TestObjectFilter_BothExtensionListsRejected(t *testing.T) {
	_, err := newObjectFilter(nil, nil, []string{"tf"}, []string{"zip"})

	assert.Error(t, err)
}

func TestObjectFilter_AxesCombine(t *testing.T) {
	filter := newTestObjectFilter(t, []string{"src/"}, nil, nil, []string{"zip"})

	assert.True(t, filter.shouldInclude("src/main.go"))
	assert.False(t, filter.shouldInclude("src/bundle.zip"), "passes the prefix axis, fails the extension axis")
	assert.False(t, filter.shouldInclude("docs/guide.md"), "passes the extension axis, fails the prefix axis")
}

// Enterprise passes these lists as newline separated text, which can yield blank
// entries. A blank exclude prefix would otherwise match every key and skip the
// whole bucket.
func TestObjectFilter_BlankEntriesIgnored(t *testing.T) {
	filter := newTestObjectFilter(t, nil, []string{""}, nil, []string{""})

	assert.True(t, filter.shouldInclude("any/key.zip"))
}

// A list holding only blanks is not a populated list, so it cannot conflict with
// the opposite list.
func TestObjectFilter_BlankExtensionListIsNotAConflict(t *testing.T) {
	filter := newTestObjectFilter(t, nil, nil, []string{""}, []string{"zip"})

	assert.False(t, filter.shouldInclude("build/artifact.zip"))
	assert.True(t, filter.shouldInclude("infra/main.tf"))
}

// Padded entries reach the filter from config files and shell arguments. Without
// trimming they match nothing, so an exclusion the user configured would silently
// do nothing.
func TestObjectFilter_EntriesAreTrimmed(t *testing.T) {
	prefixFilter := newTestObjectFilter(t, nil, []string{"archive/\r"}, nil, nil)
	assert.False(t, prefixFilter.shouldInclude("archive/a.txt"))

	extFilter := newTestObjectFilter(t, nil, nil, nil, []string{" zip "})
	assert.False(t, extFilter.shouldInclude("build/artifact.zip"))

	whitespaceOnly := newTestObjectFilter(t, nil, []string{"   "}, nil, nil)
	assert.True(t, whitespaceOnly.shouldInclude("any/key.txt"))
}
