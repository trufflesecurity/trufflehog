package custom_detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVarString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantVars map[string]int
	}{
		{
			name:     "empty",
			input:    "{}",
			wantVars: map[string]int{},
		},
		{
			name:  "no subgroup",
			input: "{hello}",
			wantVars: map[string]int{
				"hello": 0,
			},
		},
		{
			name:  "with subgroup",
			input: "{hello.123}",
			wantVars: map[string]int{
				"hello": 123,
			},
		},
		{
			name:  "subgroup with spaces",
			input: "{\thell0  . 123  }",
			wantVars: map[string]int{
				"hell0": 123,
			},
		},
		{
			name:  "multiple groups",
			input: "foo {bar} {bazz.buzz} {buzz.2}",
			wantVars: map[string]int{
				"bar":  0,
				"buzz": 2,
			},
		},
		{
			name:  "nested groups",
			input: "{foo {bar}}",
			wantVars: map[string]int{
				"bar": 0,
			},
		},
		{
			name:  "decimal without number",
			input: "{foo.}",
			wantVars: map[string]int{
				"foo": 0,
			},
		},
		{
			name:     "negative number",
			input:    "{foo.-1}",
			wantVars: map[string]int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRegexVarString(tt.input)
			assert.Equal(t, tt.input, got.original)
			assert.Equal(t, tt.wantVars, got.variables)
		})
	}
}
