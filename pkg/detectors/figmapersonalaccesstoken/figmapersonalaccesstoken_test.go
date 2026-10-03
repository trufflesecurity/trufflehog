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
		body         string
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
			name:         "403 invalid token is unverified without error",
			statusCode:   403,
			body:         `{"status":403,"err":"Invalid token"}`,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "403 missing scope is a live token",
			statusCode:   403,
			body:         `{"status":403,"err":"Invalid scope(s): file_comments:read. This endpoint requires the current_user:read scope"}`,
			wantVerified: true,
			wantErr:      false,
		},
		{
			name:         "403 with an unrecognised message is indeterminate",
			statusCode:   403,
			body:         `{"status":403,"err":"Request denied"}`,
			wantVerified: false,
			wantErr:      true,
		},
		{
			name:         "403 with an unparseable body is indeterminate",
			statusCode:   403,
			body:         "not json",
			wantVerified: false,
			wantErr:      true,
		},
		{
			name:         "401 Unauthorized is unverified with no error",
			statusCode:   401,
			wantVerified: false,
			wantErr:      false,
		},
		{
			name:         "429 rate limited is unverified with error",
			statusCode:   429,
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
			client := common.ConstantResponseHttpClient(tt.statusCode, tt.body)
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
