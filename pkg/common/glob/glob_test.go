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
			assert.Equal(t, !tt.shouldInclude, filter.Pass(tt.input))
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
	// This is effectively the same as only an include filter.
	filter, err := NewGlobFilter(WithExcludeGlobs("foo*"), WithIncludeGlobs("bar*"))
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"foo", false},
		globTest{"bar", true},
		globTest{"bara", true},
		globTest{"barb", true},
		globTest{"barbosa", true},
		globTest{"foobar", false},
		globTest{"food", false},
		globTest{"ambiguous anything else", false},
	)
}

func TestGlobFilterExcludePrecdence(t *testing.T) {
	filter, err := NewGlobFilter(WithExcludeGlobs("foo"), WithIncludeGlobs("foo*"))
	assert.NoError(t, err)

	testGlobs(t, filter,
		globTest{"foo", false},
		globTest{"foobar", true},
	)
}
