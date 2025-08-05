//go:build detectors
// +build detectors

package hashicorpvaultauth

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

func TestHashiCorpVaultAuth_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	roleId := testSecrets.MustGetField("HASHICORPVAULTAUTH_ROLE_ID")
	secretId := testSecrets.MustGetField("HASHICORPVAULTAUTH_SECRET_ID")
	inactiveRoleId := testSecrets.MustGetField("HASHICORPVAULTAUTH_ROLE_ID_INACTIVE")
	inactiveSecretId := testSecrets.MustGetField("HASHICORPVAULTAUTH_SECRET_ID_INACTIVE")
	vaultUrl := testSecrets.MustGetField("HASHICORPVAULTAUTH_URL")

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
			name: "found, unverified - complete set with invalid credentials",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("hashicorp config:\nrole_id: %s\nsecret_id: %s\nvault_url: %s", inactiveRoleId, inactiveSecretId, vaultUrl)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType:          detectorspb.DetectorType_HashiCorpVaultAuth,
					Verified:              false,
					VerificationFromCache: false,
					Raw:                   []byte(inactiveSecretId),
					RawV2:                 []byte(fmt.Sprintf("%s:%s", inactiveRoleId, inactiveSecretId)),
					ExtraData: map[string]string{
						"URL": vaultUrl,
					},
					StructuredData: nil,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, verified - complete set with valid credentials",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("hashicorp config:\nrole_id: %s\nsecret_id: %s\nvault_url: %s", roleId, secretId, vaultUrl)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType:          detectorspb.DetectorType_HashiCorpVaultAuth,
					Verified:              true,
					VerificationFromCache: false,
					Raw:                   []byte(secretId),
					RawV2:                 []byte(fmt.Sprintf("%s:%s", roleId, secretId)),
					ExtraData: map[string]string{
						"URL": vaultUrl,
					},
					StructuredData: nil,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, incomplete set - credentials without vault url",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("vault config:\nrole_id: %s\nsecret_id: %s", roleId, secretId)),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, incomplete set - only role_id",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("vault role_id: %s", roleId)),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, incomplete set - only secret_id",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("vault secret_id: %s", secretId)),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found - no vault context",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:                nil,
			wantErr:             false,
			wantVerificationErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashiCorpVaultAuth.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				if (got[i].VerificationError() != nil) != tt.wantVerificationErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.wantVerificationErr, got[i].VerificationError())
				}
			}
			// Fix: Ignore ALL unexported fields using cmpopts.IgnoreUnexported
			ignoreOpts := cmpopts.IgnoreUnexported(detectors.Result{})
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("HashiCorpVaultAuth.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
