package github

import (
	"testing"
)

func TestNormalizeGitHubEnterpriseEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// GitHub.com endpoints - should NOT be modified
		{
			name:     "github.com api endpoint",
			input:    "https://api.github.com",
			expected: "https://api.github.com",
		},
		{
			name:     "github.com api endpoint with trailing slash",
			input:    "https://api.github.com/",
			expected: "https://api.github.com",
		},
		{
			name:     "github.com api endpoint with http",
			input:    "http://api.github.com",
			expected: "http://api.github.com",
		},

		// GitHub Enterprise without /api/v3 - should ADD it
		{
			name:     "enterprise endpoint without api/v3",
			input:    "https://github.company.com",
			expected: "https://github.company.com/api/v3",
		},
		{
			name:     "enterprise endpoint with http protocol",
			input:    "http://github.company.com",
			expected: "http://github.company.com/api/v3",
		},
		{
			name:     "enterprise endpoint with trailing slash",
			input:    "https://github.company.com/",
			expected: "https://github.company.com/api/v3",
		},

		// GitHub Enterprise WITH /api/v3 - should NOT modify
		{
			name:     "enterprise endpoint already has api/v3",
			input:    "https://github.company.com/api/v3",
			expected: "https://github.company.com/api/v3",
		},
		{
			name:     "enterprise endpoint with api/v3 and trailing slash",
			input:    "https://github.company.com/api/v3/",
			expected: "https://github.company.com/api/v3",
		},
		{
			name:     "enterprise endpoint with api/v3 (http)",
			input:    "http://github.company.com/api/v3",
			expected: "http://github.company.com/api/v3",
		},

		// Edge cases
		{
			name:     "enterprise subdomain",
			input:    "https://git.enterprise.example.com",
			expected: "https://git.enterprise.example.com/api/v3",
		},
		{
			name:     "enterprise with port",
			input:    "https://github.company.com:8443",
			expected: "https://github.company.com:8443/api/v3",
		},
		{
			name:     "enterprise with port and api/v3",
			input:    "https://github.company.com:8443/api/v3",
			expected: "https://github.company.com:8443/api/v3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeGitHubEnterpriseEndpoint(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeGitHubEnterpriseEndpoint(%q) = %q, want %q",
					tt.input, result, tt.expected)
			}
		})
	}
}
