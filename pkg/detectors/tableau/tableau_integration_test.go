//go:build detectors
// +build detectors

package tableau

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestTableau_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors3")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	tokenName := testSecrets.MustGetField("TABLEAU_TOKEN_NAME")
	tokenSecret := testSecrets.MustGetField("TABLEAU_TOKEN_SECRET")
	inactiveTokenName := testSecrets.MustGetField("TABLEAU_INACTIVE_TOKEN_NAME")
	inactiveTokenSecret := testSecrets.MustGetField("TABLEAU_INACTIVE_TOKEN_SECRET")
	tableauURL := testSecrets.MustGetField("TABLEAU_VALID_POD_NAME")
	invalidURL := testSecrets.MustGetField("TABLEAU_INVALID_POD_NAME")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name                string
		s                   Scanner
		args                args
		want                []detectors.Result
		wantErr             bool
		wantVerificationErr bool
	}{
		{
			name: "found, verified with URL",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("tableau pat_name = '%s'\ntableau pat_secret = '%s'\nserver = '%s'", tokenName, tokenSecret, tableauURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     true,
					ExtraData: map[string]string{
						"token_name":            tokenName,
						"token_secret":          tokenSecret,
						"endpoint":              tableauURL,
						"credential_type":       "personal_access_token",
						"verification_endpoint": "https://" + tableauURL + "/api/3.26/auth/signin",
						"http_status":           "200",
						"verification_method":   "tableau_pat_auth",
						"verification_status":   "valid",
						"auth_token_received":   "true",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, verified without URL (using default)",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("tableau pat_name = '%s'\ntableau pat_secret = '%s'", tokenName, tokenSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     true,
					ExtraData: map[string]string{
						"token_name":            tokenName,
						"token_secret":          tokenSecret,
						"endpoint":              tableauURL, // Should use default endpoint
						"credential_type":       "personal_access_token",
						"verification_endpoint": "https://" + tableauURL + "/api/3.26/auth/signin",
						"http_status":           "200",
						"verification_method":   "tableau_pat_auth",
						"verification_status":   "valid",
						"auth_token_received":   "true",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("tableau pat_name = '%s'\ntableau pat_secret = '%s'\nserver = '%s'", tokenName, tokenSecret, tableauURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false,
					ExtraData: map[string]string{
						"token_name":      tokenName,
						"token_secret":    tokenSecret,
						"endpoint":        tableauURL,
						"credential_type": "personal_access_token",
					},
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "Internal Server Error")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("tableau pat_name = '%s'\ntableau pat_secret = '%s'\nserver = '%s'", tokenName, tokenSecret, tableauURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false,
					ExtraData: map[string]string{
						"token_name":            tokenName,
						"token_secret":          tokenSecret,
						"endpoint":              tableauURL,
						"credential_type":       "personal_access_token",
						"verification_endpoint": "https://" + tableauURL + "/api/3.26/auth/signin",
						"http_status":           "500",
						"verification_method":   "tableau_pat_auth",
						"verification_status":   "error",
					},
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, unverified with invalid URL",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("tableau pat_name = '%s'\ntableau pat_secret = '%s'\nserver = '%s'", tokenName, tokenSecret, invalidURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false,
					ExtraData: map[string]string{
						"token_name":            tokenName,
						"token_secret":          tokenSecret,
						"endpoint":              invalidURL,
						"credential_type":       "personal_access_token",
						"verification_endpoint": "https://" + invalidURL + "/api/3.26/auth/signin",
						"http_status":           "404", // or whatever status invalid URL returns
						"verification_method":   "tableau_pat_auth",
						"verification_status":   "error",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified with inactive token",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("tableau pat_name = '%s'\ntableau pat_secret = '%s'\nserver = '%s'", inactiveTokenName, inactiveTokenSecret, tableauURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false,
					ExtraData: map[string]string{
						"token_name":            inactiveTokenName,
						"token_secret":          inactiveTokenSecret,
						"endpoint":              tableauURL,
						"credential_type":       "personal_access_token",
						"verification_endpoint": "https://" + tableauURL + "/api/3.26/auth/signin",
						"http_status":           "401",
						"verification_method":   "tableau_pat_auth",
						"verification_status":   "invalid",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the tableau secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "found, unverified - malformed token",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("tableau pat_name = 'TestToken'\ntableau pat_secret = 'malformed_secret_format'"),
				verify: true,
			},
			want:    nil, // Should not find due to invalid secret format
			wantErr: false,
		},
		{
			name: "found multiple, mixed verification results with URLs",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(fmt.Sprintf(`
					tableau pat_name = '%s'
					tableau token_name = '%s'  
					tableau pat_secret = '%s'
					tableau token_secret = '%s'
					server1 = '%s'
					server2 = '%s'
				`, tokenName, inactiveTokenName, tokenSecret, inactiveTokenSecret, tableauURL, invalidURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     true, // tokenName + tokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false, // tokenName + tokenSecret + invalid URL
				},
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false, // tokenName + inactiveTokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false, // tokenName + inactiveTokenSecret + invalid URL
				},
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false, // inactiveTokenName + tokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false, // inactiveTokenName + tokenSecret + invalid URL
				},
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false, // inactiveTokenName + inactiveTokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_Tableau,
					Verified:     false, // inactiveTokenName + inactiveTokenSecret + invalid URL
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Tableau.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Errorf("Tableau.FromData() verificationError = %v, wantVerificationErr %v", got[i].VerificationError(), tt.wantVerificationErr)
				}
			}

			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError", "ExtraData")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Tableau.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}

			// Verify that ExtraData contains expected keys
			for i, result := range got {
				if tt.want != nil && i < len(tt.want) {
					if result.ExtraData != nil {
						// Check that essential ExtraData fields are present
						if _, exists := result.ExtraData["token_name"]; !exists {
							t.Errorf("Expected token_name in ExtraData")
						}
						if _, exists := result.ExtraData["token_secret"]; !exists {
							t.Errorf("Expected token_secret in ExtraData")
						}
						if _, exists := result.ExtraData["endpoint"]; !exists {
							t.Errorf("Expected endpoint in ExtraData")
						}
						if result.Verified {
							if _, exists := result.ExtraData["verification_status"]; !exists {
								t.Errorf("Expected verification_status in ExtraData for verified result")
							}
						}
					}
				}
			}
		})
	}
}
