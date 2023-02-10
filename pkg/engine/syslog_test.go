package engine

import (
	"sync"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestScanSyslog(t *testing.T) {
	tests := []struct {
		name    string
		c       sources.Config
		wantErr bool
	}{
		{
			name: "Scan syslog successfully",
			c: sources.Config{
				Protocol:    "tcp",
				Address:     "127.0.0.1:1514",
				Format:      "rfc3164",
				Concurrency: 1,
			},
			wantErr: false,
		},
		{
			name: "Scan syslog with invalid cert",
			c: sources.Config{
				CertPath:    "bad",
				KeyPath:     "valid",
				Address:     "127.0.0.1:1514",
				Format:      "rfc3164",
				Concurrency: 1,
			},
			wantErr: true,
		},
		{
			name: "Scan syslog with invalid keypath",
			c: sources.Config{
				Protocol:    "tcp",
				KeyPath:     "invalid",
				CertPath:    "valid",
				Format:      "rfc3164",
				Concurrency: 1,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Engine{
				sourcesWg: sync.WaitGroup{},
			}
			ctx := context.Background()
			if err := e.ScanSyslog(ctx, tt.c); (err != nil) != tt.wantErr {
				t.Errorf("ScanSyslog() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
