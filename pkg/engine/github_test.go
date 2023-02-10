package engine

import (
	"sync"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestEngine_ScanGitHub(t *testing.T) {
	tests := []struct {
		name    string
		config  sources.Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: sources.Config{
				Endpoint:     "https://api.github.com",
				Token:        "valid_token",
				Orgs:         []string{"org1", "org2"},
				Repos:        []string{"repo1", "repo2"},
				IncludeForks: true,
			},
		},
		{
			name: "empty endpoint",
			config: sources.Config{
				Endpoint: "",
				Token:    "valid_token",
				Orgs:     []string{"org1", "org2"},
			},
		},
		{
			name: "empty token",
			config: sources.Config{
				Endpoint: "https://api.github.com",
				Orgs:     []string{"org1", "org2"},
			},
		},
		{
			name: "empty orgs",
			config: sources.Config{
				Endpoint: "https://api.github.com",
				Token:    "valid_token",
				Orgs:     []string{},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := &Engine{
				sourcesWg: sync.WaitGroup{},
			}
			ctx := context.Background()
			err := e.ScanGitHub(ctx, test.config)
			if (err != nil) != test.wantErr {
				t.Errorf("ScanGitHub(%v) error = %v, wantErr %v", test.config, err, test.wantErr)
			}
		})
	}
}
