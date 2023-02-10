package engine

import (
	"sync"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestEngine_ScanFileSystem(t *testing.T) {
	tests := []struct {
		name    string
		config  sources.FilesystemConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: sources.FilesystemConfig{
				Directories: []string{"/tmp"},
			},
		},
		{
			name: "empty directories",
			config: sources.FilesystemConfig{
				Directories: []string{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := &Engine{
				sourcesWg: sync.WaitGroup{},
			}

			ctx := context.Background()
			err := e.ScanFileSystem(ctx, test.config)
			if (err != nil) != test.wantErr {
				t.Errorf("ScanFileSystem(%v) error = %v, wantErr %v", test.config, err, test.wantErr)
			}
		})
	}
}
