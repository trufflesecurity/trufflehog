package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		want     map[string][]string
		wantErrs int
	}{
		{
			name:     "no input",
			input:    nil,
			want:     map[string][]string{},
			wantErrs: 0,
		},
		{
			name:     "simple Name: value",
			input:    []string{"X-Scanner-Id: abc"},
			want:     map[string][]string{"X-Scanner-Id": {"abc"}},
			wantErrs: 0,
		},
		{
			name:     "no whitespace after colon",
			input:    []string{"X-Foo:bar"},
			want:     map[string][]string{"X-Foo": {"bar"}},
			wantErrs: 0,
		},
		{
			name:     "extra whitespace trimmed",
			input:    []string{"  X-Foo  :  bar  "},
			want:     map[string][]string{"X-Foo": {"bar"}},
			wantErrs: 0,
		},
		{
			name:     "value containing colons preserved (URL)",
			input:    []string{"X-Callback: https://example.com/cb"},
			want:     map[string][]string{"X-Callback": {"https://example.com/cb"}},
			wantErrs: 0,
		},
		{
			name:     "empty value allowed (RFC 7230)",
			input:    []string{"X-Empty:"},
			want:     map[string][]string{"X-Empty": {""}},
			wantErrs: 0,
		},
		{
			name:     "multiple values for same name",
			input:    []string{"X-Foo: a", "X-Foo: b"},
			want:     map[string][]string{"X-Foo": {"a", "b"}},
			wantErrs: 0,
		},
		{
			name:     "no separator rejected",
			input:    []string{"BadHeader"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
		{
			name:     "empty name rejected",
			input:    []string{": value"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
		{
			name:     "whitespace-only name rejected",
			input:    []string{"   : value"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
		{
			name:     "name with space rejected",
			input:    []string{"Bad Name: value"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
		{
			name:     "name with CRLF rejected",
			input:    []string{"X-Foo\r\nX-Bar: smuggled"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
		{
			name:     "value with CR rejected",
			input:    []string{"X-Foo: bad\rvalue"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
		{
			name:     "value with LF rejected",
			input:    []string{"X-Foo: bad\nvalue"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
		{
			name:  "valid + invalid in same call: both reported",
			input: []string{"X-Good: ok", "BadHeader", "X-Also-Good: yes"},
			want: map[string][]string{
				"X-Good":      {"ok"},
				"X-Also-Good": {"yes"},
			},
			wantErrs: 1,
		},
		{
			name:     "equals is NOT a separator (legacy support dropped)",
			input:    []string{"X-Foo=bar"},
			want:     map[string][]string{},
			wantErrs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			hdr, errs := ParseHeaders(tt.input)
			assert.Len(t, errs, tt.wantErrs, "unexpected error count")
			assert.Equal(t, len(tt.want), len(hdr), "unexpected header count")
			for k, vals := range tt.want {
				assert.Equal(t, vals, hdr.Values(k), "values for %s", k)
			}
		})
	}
}
