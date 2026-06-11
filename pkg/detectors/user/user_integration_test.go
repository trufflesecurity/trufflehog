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
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("User.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
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
