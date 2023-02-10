package engine

import (
	"sync"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestScanGitLab(t *testing.T) {
	tests := []struct {
		name    string
		c       sources.GitlabConfig
		wantErr bool
	}{
		{
			name: "Successful scan with valid token and endpoint",
			c: sources.GitlabConfig{
				Token:    "valid-token",
				Endpoint: "https://gitlab.com",
				Repos:    []string{"repo1", "repo2"},
			},
		},
		{
			name: "Failed scan with empty token",
			c: sources.GitlabConfig{
				Token:    "",
				Endpoint: "https://gitlab.com",
				Repos:    []string{"repo1", "repo2"},
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			e := &Engine{
				sourcesWg: sync.WaitGroup{},
			}

			err := e.ScanGitLab(ctx, test.c)
			if (err != nil) != test.wantErr {
				t.Errorf("ScanGitLab(%v) error = %v, wantErr %v", test.c, err, test.wantErr)
			}
		})
	}
}
