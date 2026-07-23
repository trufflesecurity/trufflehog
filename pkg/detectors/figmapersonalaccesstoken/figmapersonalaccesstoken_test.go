package figmapersonalaccesstoken

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

func TestVerifyMatch(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "200 OK is verified",
			statusCode:   200,
			wantVerified: true,
			wantErr:      false,
		},
		{
			name:         "401 Unauthorized is unverified without error",
			statusCode:   401,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "403 Forbidden is unverified without error",
			statusCode:   403,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "404 Not Found is unverified with error",
			statusCode:   404,
			wantVerified: false,
			wantErr:      true,
		},
		{
			name:         "500 Internal Server Error is unverified with error",
			statusCode:   500,
			wantVerified: false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(tt.statusCode, "")
			verified, err := VerifyMatch(context.Background(), client, "figp_test_token")

			if verified != tt.wantVerified {
				t.Errorf("VerifyMatch() verified = %v, want %v", verified, tt.wantVerified)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyMatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
