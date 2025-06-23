package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestPostmanEngine(t *testing.T) {
	tests := []struct {
		name          string
		postmanConfig sources.PostmanConfig
		wantErr       bool
	}{
		{
			name: "scanned Postman with a token",
			postmanConfig: sources.PostmanConfig{
				Token: "dummy_key",
			},
		},
		{
			name: "scanned Postman with workspacePath",
			postmanConfig: sources.PostmanConfig{
				WorkspacePaths: []string{"Downloads/Test API.postman_collection.json"},
			},
		},
		{
			name: "scanned Postman with environmentPath",
			postmanConfig: sources.PostmanConfig{
				EnvironmentPaths: []string{"Downloads/Mobile - Points Unlock Redeemables.postman_environment.json"},
			},
		},
		{
			name:    "no token or file path provided",
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			const defaultOutputBufferSize = 64
			opts := []func(*sources.SourceManager){
				sources.WithSourceUnits(),
				sources.WithBufferedOutput(defaultOutputBufferSize),
			}

			sourceManager := sources.NewManager(opts...)

			conf := Config{
				Concurrency:   1,
				Decoders:      decoders.DefaultDecoders(),
				Detectors:     defaults.DefaultDetectors(),
				Verify:        false,
				SourceManager: sourceManager,
				Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
			}

			e, err := NewEngine(ctx, &conf)
			assert.NoError(t, err)
			e.Start(ctx)
			_, err = e.ScanPostman(ctx, test.postmanConfig)
			if err != nil && !test.wantErr {
				t.Errorf("ScanPostman() got: %v, want: %v", err, nil)
				return
			}
			if err == nil && test.wantErr {
				t.Errorf("ScanPostman() got: %v, want: %v", err, "error")
			}
		})
	}
}
