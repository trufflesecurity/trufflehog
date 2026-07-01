package git

import "testing"

func TestCheckGitVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{name: "supported version", version: "git version 2.39.5\n", wantErr: false},
		{name: "minimum supported version", version: "git version 2.20.0\n", wantErr: false},
		{name: "apple git suffix", version: "git version 2.39.5 (Apple Git-154)\n", wantErr: false},
		// Dev builds report a non-numeric patch component; this previously panicked
		// with "index out of range [1] with length 1". See issue #4801.
		{name: "non-numeric patch component", version: "git version 2.52.gaea8cc3\n", wantErr: false},
		{name: "too old", version: "git version 2.19.1\n", wantErr: true},
		{name: "major too new", version: "git version 3.0.0\n", wantErr: true},
		{name: "unparseable output", version: "git version unknown\n", wantErr: true},
		{name: "empty output", version: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkGitVersion(tt.version)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkGitVersion(%q) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}
