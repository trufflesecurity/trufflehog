package giturl

import "testing"

func TestTrimGitSuffix(t *testing.T) {
	tests := []struct {
		name string
		repo string
		want string
	}{
		{"with .git suffix", "https://github.com/owner/repo.git", "https://github.com/owner/repo"},
		{"without .git suffix", "https://github.com/owner/repo", "https://github.com/owner/repo"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrimGitSuffix(tt.repo); got != tt.want {
				t.Errorf("TrimGitSuffix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodeSpecialChars(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"no special chars", "path/to/file.go", "path/to/file.go"},
		{"percent sign", "path/with%percent.go", "path/with%25percent.go"},
		{"square brackets", "path/with[brackets].go", "path/with%5Bbrackets%5D.go"},
		{"all special chars", "path%[test].go", "path%25%5Btest%5D.go"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncodeSpecialChars(tt.path); got != tt.want {
				t.Errorf("EncodeSpecialChars() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGistURL(t *testing.T) {
	tests := []struct {
		name string
		repo string
		want bool
	}{
		{"github gist", "https://gist.github.com/user/abc123.git", true},
		{"github repo", "https://github.com/owner/repo.git", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGistURL(tt.repo); got != tt.want {
				t.Errorf("IsGistURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsWikiURL(t *testing.T) {
	tests := []struct {
		name string
		repo string
		want bool
	}{
		{"github wiki", "https://github.com/owner/repo.wiki.git", true},
		{"github repo", "https://github.com/owner/repo.git", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsWikiURL(tt.repo); got != tt.want {
				t.Errorf("IsWikiURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimWikiSuffix(t *testing.T) {
	tests := []struct {
		name string
		repo string
		want string
	}{
		{"with .wiki.git suffix", "https://github.com/owner/repo.wiki.git", "https://github.com/owner/repo"},
		{"without suffix", "https://github.com/owner/repo.git", "https://github.com/owner/repo.git"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrimWikiSuffix(tt.repo); got != tt.want {
				t.Errorf("TrimWikiSuffix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCleanGistFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{"single extension", "config.yaml", "config-yaml"},
		{"multiple extensions", "config.yaml.example", "config-yaml-example"},
		{"no extension", "README", "README"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CleanGistFilename(tt.filename); got != tt.want {
				t.Errorf("CleanGistFilename() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrimFileExtension(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"with extension", "docs/README.md", "docs/README"},
		{"without extension", "docs/README", "docs/README"},
		{"empty string", "", ""},
		{"hidden file", ".gitignore", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrimFileExtension(tt.path); got != tt.want {
				t.Errorf("TrimFileExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}
