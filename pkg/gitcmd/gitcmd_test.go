package gitcmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseGitVersion(t *testing.T) {
	tests := []struct {
		name      string
		out       string
		wantMajor int
		wantMinor int
		wantErr   bool
	}{
		{
			name:      "standard semver",
			out:       "git version 2.34.1\n",
			wantMajor: 2,
			wantMinor: 34,
		},
		{
			name:      "non-numeric patch (built from source)",
			out:       "git version 2.52.gaea8cc3\n",
			wantMajor: 2,
			wantMinor: 52,
		},
		{
			name:      "apple git suffix",
			out:       "git version 2.39.2 (Apple Git-143)\n",
			wantMajor: 2,
			wantMinor: 39,
		},
		{
			name:      "windows git suffix",
			out:       "git version 2.39.2.windows.1\n",
			wantMajor: 2,
			wantMinor: 39,
		},
		{
			name:      "no patch component",
			out:       "git version 2.20\n",
			wantMajor: 2,
			wantMinor: 20,
		},
		{
			name:    "no version present",
			out:     "git is not a version\n",
			wantErr: true,
		},
		{
			name:    "empty output",
			out:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, err := parseGitVersion(tt.out)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantMajor, major)
			assert.Equal(t, tt.wantMinor, minor)
		})
	}
}
