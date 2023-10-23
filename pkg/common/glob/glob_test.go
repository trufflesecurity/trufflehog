package glob

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"
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

func TestGlobErrorContainsGlob(t *testing.T) {
	invalidGlob := "[this is invalid because it doesn't close the capture group"
	_, err := NewGlobFilter(WithExcludeGlobs(invalidGlob))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), invalidGlob)
}

// The filters in this test should be mutually exclusive because one includes
// and the other excludes the same glob.
func TestGlobInverse(t *testing.T) {
	for _, glob := range []string{
		"a",
		"a*",
		"a**",
		"*a",
		"**a",
		"*",
	} {
		include, err := NewGlobFilter(WithIncludeGlobs(glob))
		assert.NoError(t, err)
		exclude, err := NewGlobFilter(WithExcludeGlobs(glob))
		assert.NoError(t, err)
		rapid.Check(t, func(t *rapid.T) {
			input := rapid.String().Draw(t, "input")
			a, b := include.ShouldInclude(input), exclude.ShouldInclude(input)
			if a == b {
				t.Fatalf("Filter(Include(%q)) == Filter(Exclude(%q)) == %v for input %q", glob, glob, a, input)
			}
		})
	}
}

func TestGlobDefaultFilters(t *testing.T) {
	for _, filter := range []*Filter{nil, {}} {
		rapid.Check(t, func(t *rapid.T) {
			if !filter.ShouldInclude(rapid.String().Draw(t, "input")) {
				t.Fatalf("filter %#v did not include input", filter)
			}
		})
	}
}
