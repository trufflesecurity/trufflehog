package engine

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestScanGCS(t *testing.T) {
	tests := []struct {
		name      string
		gcsConfig sources.GCSConfig
		wantErr   bool
	}{
		{
			name: "scanned GCS",
			gcsConfig: sources.GCSConfig{
				ApiKey:    "abc123",
				ProjectID: "test-project",
			},
		},
		{
			name: "missing API key",
			gcsConfig: sources.GCSConfig{
				ApiKey:    "",
				ProjectID: "test-project",
			},
		},
		{
			name: "missing project ID",
			gcsConfig: sources.GCSConfig{
				ApiKey: "abc123",
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := &Engine{}
			err := e.ScanGCS(context.Background(), test.gcsConfig)
			if err != nil && !test.wantErr {
				t.Errorf("ScanGCS() got: %v, want: %v", err, nil)
			}

		})
	}
}
