package engine

import (
	"strings"
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
				ApiKey:         "abc123",
				ProjectID:      "test-project",
				CloudCred:      false,
				WithoutAuth:    false,
				ServiceAccount: "",
			},
		},
		{
			name:      "missing project ID, with auth",
			gcsConfig: sources.GCSConfig{ApiKey: "abc123"},
			wantErr:   true,
		},
		{
			name:      "missing project ID, without auth, public scan",
			gcsConfig: sources.GCSConfig{WithoutAuth: true},
		},
		{
			name: "multiple selected auth methods",
			gcsConfig: sources.GCSConfig{
				ApiKey:         "abc123",
				ProjectID:      "test-project",
				CloudCred:      true,
				WithoutAuth:    false,
				ServiceAccount: "",
			},
			wantErr: true,
		},
		{
			name: "no auth method selected",
			gcsConfig: sources.GCSConfig{
				ProjectID:     "test-project",
				MaxObjectSize: 10 * 1024 * 1024,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := &Engine{}
			err := e.ScanGCS(context.Background(), test.gcsConfig)
			if err != nil && !test.wantErr && !strings.Contains(err.Error(), "googleapi: Error 400: Bad Request") {
				t.Errorf("ScanGCS() got: %v, want: %v", err, nil)
				return
			}

			if err == nil && test.wantErr {
				t.Errorf("ScanGCS() got: %v, want: %v", err, "error")
			}
		})
	}
}
