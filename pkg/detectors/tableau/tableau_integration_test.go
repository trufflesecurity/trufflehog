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
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
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
				data:   []byte(fmt.Sprintf("token=%s\nsecret=%s\nserver=%s", tokenName, tokenSecret, tableauURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
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
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "Internal Server Error")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("name = '%s'\n secret = '%s'\nserver = '%s'", tokenName, tokenSecret, tableauURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
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
				data:   []byte(fmt.Sprintf("name = '%s'\nsecret = '%s'\nserver = '%s'", tokenName, tokenSecret, invalidURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
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
				data:   []byte(fmt.Sprintf("name = '%s'\n secret = '%s'\nserver = '%s'", inactiveTokenName, inactiveTokenSecret, tableauURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
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
					name1 = '%s'
					name2 = '%s'
					secret = '%s'
					secret2 = '%s'
					server1 = '%s'
					server2 = '%s'
				`, tokenName, inactiveTokenName, tokenSecret, inactiveTokenSecret, tableauURL, invalidURL)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     true, // tokenName + tokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     false, // tokenName + tokenSecret + invalid URL
				},
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     false, // tokenName + inactiveTokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     false, // tokenName + inactiveTokenSecret + invalid URL
				},
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     false, // inactiveTokenName + tokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     false, // inactiveTokenName + tokenSecret + invalid URL
				},
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     false, // inactiveTokenName + inactiveTokenSecret + valid URL
				},
				{
					DetectorType: detectorspb.DetectorType_TableauPersonalAccessToken,
					Verified:     false, // inactiveTokenName + inactiveTokenSecret + invalid URL
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Enable found endpoints for tests that need URL detection
			scanner := tt.s
			scanner.UseFoundEndpoints(true)

			got, err := scanner.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Tableau.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check that we got the expected number of results
			if len(got) != len(tt.want) {
				t.Errorf("Tableau.FromData() got %d results, want %d", len(got), len(tt.want))
			}

			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Errorf("Tableau.FromData() verificationError = %v, wantVerificationErr %v", got[i].VerificationError(), tt.wantVerificationErr)
				}
			}

			ignoreOpts := []cmp.Option{
				cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError", "ExtraData"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
			}

			if diff := cmp.Diff(got, tt.want, ignoreOpts...); diff != "" {
				t.Errorf("Tableau.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
