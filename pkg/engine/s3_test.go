package engine

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestScanS3(t *testing.T) {
	tests := []struct {
		name      string
		c         sources.Config
		expectErr bool
	}{
		{
			name: "Test with cloud credentials",
			c: sources.Config{
				CloudCred: true,
				Buckets:   []string{"bucket1", "bucket2"},
			},
			expectErr: false,
		},
		{
			name: "Test with basic authentication",
			c: sources.Config{
				CloudCred: false,
				Key:       "accessKey",
				Secret:    "secretKey",
				Buckets:   []string{"bucket1", "bucket2"},
			},
			expectErr: false,
		},
		{
			name: "Test with both cloud credentials and basic authentication",
			c: sources.Config{
				CloudCred: true,
				Key:       "accessKey",
				Secret:    "secretKey",
				Buckets:   []string{"bucket1", "bucket2"},
			},
			expectErr: true,
		},
		{
			name: "Test with unauthenticated",
			c: sources.Config{
				CloudCred: false,
				Buckets:   []string{"bucket1", "bucket2"},
			},
			expectErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			e := Engine{}
			err := e.ScanS3(ctx, test.c)
			if test.expectErr && err == nil {
				t.Errorf("expected an error but got nil")
			}
			if !test.expectErr && err != nil {
				t.Errorf("expected no error but got %v", err)
			}
		})
	}
}
