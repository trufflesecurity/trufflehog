package common

import (
	"os"
	"testing"
)

func TestExpandEnvSafe(t *testing.T) {
	t.Setenv("FOO", "BAR")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "expand $VAR",
			in:   "x$FOO y",
			want: "xBAR y",
		},
		{
			name: "expand ${VAR}",
			in:   "x${FOO}y",
			want: "xBARy",
		},
		{
			name: "do not expand $?",
			in:   "$?",
			want: "$?",
		},
		{
			name: "do not expand $@",
			in:   "$@",
			want: "$@",
		},
		{
			name: "do not expand $1",
			in:   "$1",
			want: "$1",
		},
		{
			name: "do not mangle incomplete ${VAR",
			in:   "${SOMETHING",
			want: "${SOMETHING",
		},
		{
			name: "do not expand $(...)",
			in:   "$(",
			want: "$(",
		},
		{
			name: "do not expand invalid brace name",
			in:   "${1}",
			want: "${1}",
		},
		{
			name: "escaped dollar does not expand",
			in:   `\$FOO`,
			want: `\$FOO`,
		},
		{
			name: "regex example preserves $?, $@, and ${ without closing brace",
			in: `detectors:
  - name: Custom Detector
    regex:
      secret: |-
        (?i)password=([^ ]+)
    exclude_regexes_capture:
      - |-
        \\$?\\([A-Z$@0-9]
      - |- # ${SOMETHING
        ^foo$`,
			want: `detectors:
  - name: Custom Detector
    regex:
      secret: |-
        (?i)password=([^ ]+)
    exclude_regexes_capture:
      - |-
        \\$?\\([A-Z$@0-9]
      - |- # ${SOMETHING
        ^foo$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandEnvSafe(tt.in)
			if got != tt.want {
				t.Fatalf("ExpandEnvSafe mismatch:\n  in:   %q\n  got:  %q\n  want: %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandEnvSafe_DoesNotMatchOsExpandEnvForShellSpecials(t *testing.T) {
	// This test documents the enterprise failure mode: os.ExpandEnv removes
	// shell-special parameters like $? and $@, which can appear in regexes.
	//
	// If Go changes os.ExpandEnv behavior in the future, this test can be
	// adjusted/removed; ExpandEnvSafe must continue to preserve them.
	in := `\\$?\\([A-Z$@0-9]`

	got := ExpandEnvSafe(in)
	if got != in {
		t.Fatalf("expected ExpandEnvSafe to preserve input:\n  got: %q\n  in:  %q", got, in)
	}

	if os.ExpandEnv(in) == in {
		t.Fatalf("expected os.ExpandEnv to differ from input for this case; update this test if behavior changes")
	}
}

