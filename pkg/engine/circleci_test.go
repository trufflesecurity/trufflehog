package engine

import (
	"sync"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestScanCircleCI(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:  "valid token",
			token: "valid_token",
		},
		{
			name:  "no token",
			token: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			engine := &Engine{}
			engine.sourcesWg = sync.WaitGroup{}

			err := engine.ScanCircleCI(ctx, test.token)
			if (err != nil) != test.wantErr {
				t.Errorf("ScanCircleCI() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
