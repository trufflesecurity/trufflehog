package basicauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestBasicAuth_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*1000000000) // 5 seconds
	defer cancel()

	// Create test credentials
	validCreds := base64.StdEncoding.EncodeToString([]byte("admin:password123"))
	validCredsComplex := base64.StdEncoding.EncodeToString([]byte("user@example.com:P@ssw0rd!2023"))
	invalidNoCreds := base64.StdEncoding.EncodeToString([]byte("justonefield"))
	invalidEmptyPassword := base64.StdEncoding.EncodeToString([]byte("username:"))

	tests := []struct {
		name        string
		input       string
		want        []detectors.Result
		wantErr     bool
		wantMatches int
	}{
		{
			name:        "valid basic auth with Authorization header",
			input:       fmt.Sprintf("Authorization: Basic %s", validCreds),
			wantMatches: 1,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_BasicAuth,
					Verified:     false,
					Raw:          []byte(validCreds),
					RawV2:        []byte("admin:password123"),
					SecretParts: map[string]string{
						"username": "admin",
						"password": "password123",
						"encoded":  validCreds,
					},
				},
			},
		},
		{
			name:        "valid basic auth with auth header lowercase",
			input:       fmt.Sprintf("auth: basic %s", validCreds),
			wantMatches: 1,
		},
		{
			name:        "valid basic auth with complex password",
			input:       fmt.Sprintf("Authorization: Basic %s", validCredsComplex),
			wantMatches: 1,
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_BasicAuth,
					Verified:     false,
					Raw:          []byte(validCredsComplex),
					RawV2:        []byte("user@example.com:P@ssw0rd!2023"),
					SecretParts: map[string]string{
						"username": "user@example.com",
						"password": "P@ssw0rd!2023",
						"encoded":  validCredsComplex,
					},
				},
			},
		},
		{
			name:        "basic auth with equals separator",
			input:       fmt.Sprintf("Authorization=Basic %s", validCreds),
			wantMatches: 1,
		},
		{
			name:        "basic auth in curl command",
			input:       fmt.Sprintf("curl -H 'Authorization: Basic %s' https://api.example.com", validCreds),
			wantMatches: 1,
		},
		{
			name:        "invalid - no colon separator",
			input:       fmt.Sprintf("Authorization: Basic %s", invalidNoCreds),
			wantMatches: 0,
		},
		{
			name:        "invalid - empty password",
			input:       fmt.Sprintf("Authorization: Basic %s", invalidEmptyPassword),
			wantMatches: 0,
		},
		{
			name:        "invalid - not base64",
			input:       "Authorization: Basic not-valid-base64!!!",
			wantMatches: 0,
		},
		{
			name:        "invalid - too short",
			input:       "Authorization: Basic YWRt",
			wantMatches: 0,
		},
		{
			name:        "multiple basic auth tokens",
			input:       fmt.Sprintf("Authorization: Basic %s\nAuthorization: Basic %s", validCreds, validCredsComplex),
			wantMatches: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(ctx, false, []byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("BasicAuth.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.wantMatches {
				t.Errorf("BasicAuth.FromData() got %d matches, want %d", len(got), tt.wantMatches)
				return
			}

			if tt.want != nil && len(got) > 0 {
				// Compare first result
				ignoreOpts := cmpopts.IgnoreUnexported(detectors.Result{})

				if diff := cmp.Diff(got[0], tt.want[0], ignoreOpts); diff != "" {
					t.Errorf("BasicAuth.FromData() mismatch (-got +want):\n%s", diff)
				}
			}
		})
	}
}

func TestBasicAuth_Keywords(t *testing.T) {
	s := Scanner{}
	keywords := s.Keywords()

	if len(keywords) == 0 {
		t.Error("Keywords() returned empty slice")
	}

	expectedKeywords := map[string]bool{
		"authorization": true,
		"basic":         true,
		"auth":          true,
	}

	for _, kw := range keywords {
		if !expectedKeywords[kw] {
			t.Errorf("unexpected keyword: %s", kw)
		}
	}
}
