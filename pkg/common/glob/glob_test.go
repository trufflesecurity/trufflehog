package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type globTest struct {
	input         string
	shouldInclude bool
}

func testGlobs(t *testing.T, filter *Filter, tests ...globTest) {
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// Invert because mentally it's easier to say whether an
			// input should be included.
			assert.Equal(t, tt.shouldInclude, filter.ShouldInclude(tt.input))
		})
	}
}

func TestGlobFilterExclude(t *testing.T) {
	filter, err := NewGlobFilter(WithExcludeGlobs("foo", "bar*"))
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"foo", false},
		globTest{"bar", false},
		globTest{"bara", false},
		globTest{"barb", false},
		globTest{"barbosa", false},
		globTest{"foobar", true},
		globTest{"food", true},
		globTest{"anything else", true},
	)
}

func TestGlobFilterInclude(t *testing.T) {
	filter, err := NewGlobFilter(WithIncludeGlobs("foo", "bar*"))
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"foo", true},
		globTest{"bar", true},
		globTest{"bara", true},
		globTest{"barb", true},
		globTest{"barbosa", true},
		globTest{"foobar", false},
		globTest{"food", false},
		globTest{"anything else", false},
	)
}

func TestGlobFilterEmpty(t *testing.T) {
	filter, err := NewGlobFilter()
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"foo", true},
		globTest{"bar", true},
		globTest{"bara", true},
		globTest{"barb", true},
		globTest{"barbosa", true},
		globTest{"foobar", true},
		globTest{"food", true},
		globTest{"anything else", true},
	)
}

func TestGlobFilterExcludeInclude(t *testing.T) {
	filter, err := NewGlobFilter(WithExcludeGlobs("/foo/bar/**"), WithIncludeGlobs("/foo/**"))
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"/foo/a", true},
		globTest{"/foo/b", true},
		globTest{"/foo/c/d/e", true},
		globTest{"/foo/bar/a", false},
		globTest{"/foo/bar/b", false},
		globTest{"/foo/bar/c/d/e", false},
		globTest{"/any/other/path", false},
	)
}

func TestGlobFilterExcludePrecedence(t *testing.T) {
	filter, err := NewGlobFilter(WithExcludeGlobs("foo"), WithIncludeGlobs("foo*"))
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"foo", false},
		globTest{"foobar", true},
	)
}

func TestGlobDefault(t *testing.T) {
	// Test default *Filter and Filter have the same behavior.
	for _, filter := range []*Filter{nil, {}} {
		testGlobs(t, filter,
			globTest{"foo", true},
			globTest{"bar", true},
			globTest{"bara", true},
			globTest{"barb", true},
			globTest{"barbosa", true},
			globTest{"foobar", true},
			globTest{"food", true},
			globTest{"anything else", true},
		)
	}
}

func TestGlobErrorContainsGlob(t *testing.T) {
	invalidGlob := "[this is invalid because it doesn't close the capture group"
	_, err := NewGlobFilter(WithExcludeGlobs(invalidGlob))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), invalidGlob)
}

func TestGlobDefaultDeny(t *testing.T) {
	filter, err := NewGlobFilter(
		WithExcludeGlobs("/foo/bar/**"),
		WithIncludeGlobs("/foo/**"),
		WithDefaultDeny(),
	)
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"/foo/a", true},
		globTest{"/foo/bar/a", false},
		globTest{"/any/other/path", false},
	)
}

func TestGlobDefaultAllow(t *testing.T) {
	filter, err := NewGlobFilter(
		WithExcludeGlobs("/foo/bar/**"),
		WithIncludeGlobs("/foo/**"),
		WithDefaultAllow(),
	)
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"/foo/a", true},
		globTest{"/foo/bar/a", false},
		globTest{"/any/other/path", true},
	)
}
