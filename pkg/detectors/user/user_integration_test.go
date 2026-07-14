//go:build detectors
// +build detectors

package user

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestUser_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors1")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("USER")
	inactiveSecret := testSecrets.MustGetField("USER_INACTIVE")
	endpoint := testSecrets.MustGetField("USER_ENDPOINT")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name    string
		s       Scanner
		args    args
		want    []detectors.Result
		wantErr bool
	}{
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("user token = %s\nurl = %s", secret, endpoint)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_User,
					Verified:     true,
					Raw:          []byte(secret),
					RawV2:        []byte(secret + ":" + endpoint),
					SecretParts: map[string]string{
						"key":      secret,
						"endpoint": endpoint,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("user token = %s\nurl = %s", inactiveSecret, endpoint)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_User,
					Verified:     false,
					Raw:          []byte(inactiveSecret),
					RawV2:        []byte(inactiveSecret + ":" + endpoint),
					SecretParts: map[string]string{
						"key":      inactiveSecret,
						"endpoint": endpoint,
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
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.UseFoundEndpoints(true)

			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("User.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				gotErr := ""
				if got[i].VerificationError() != nil {
					gotErr = got[i].VerificationError().Error()
				}
				wantErr := ""
				if tt.want[i].VerificationError() != nil {
					wantErr = tt.want[i].VerificationError().Error()
				}
				if gotErr != wantErr {
					t.Fatalf("wantVerificationError = %v, verification error = %v", tt.want[i].VerificationError(), got[i].VerificationError())
				}
			}
			ignoreOpts := cmpopts.IgnoreFields(
				detectors.Result{},
				"ExtraData",
				"verificationError",
				"primarySecret",
				"chunkOffset",
				"chunkOffsetSet",
			)
			if diff := cmp.Diff(tt.want, got, ignoreOpts); diff != "" {
				t.Errorf("User.FromData() %s diff: (-want +got)\n%s", tt.name, diff)
			}
		})
	}
}

func TestUser_FromChunk_WithCustomEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors1")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("USER")
	endpoint := testSecrets.MustGetField("USER_ENDPOINT")

	s := Scanner{}
	s.UseFoundEndpoints(true)
	if err := s.SetConfiguredEndpoints(endpoint); err != nil {
		t.Fatal("Error in setting configured endpoint")
	}

	data := []byte(fmt.Sprintf("user token = %s", secret))

	got, err := s.FromData(ctx, true, data)

	require.NoError(t, err, "unexpected error from FromData")
	require.Greater(t, len(got), 0, "expected at least 1 result")

	expectedRawV2 := []byte(secret + ":" + endpoint)
	if string(got[0].RawV2) != string(expectedRawV2) {
		t.Errorf("User.FromData() rawV2 mismatch: got %s, want %s", string(got[0].RawV2), string(expectedRawV2))
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
