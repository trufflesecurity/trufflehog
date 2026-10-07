//go:build detectors
// +build detectors

package cloudflareapitoken

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestCloudflareApiTokenV2_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors6")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	userToken := testSecrets.MustGetField("CLOUDFLARE_USER_API_TOKEN_V2")
	userTokenInactive := testSecrets.MustGetField("CLOUDFLARE_USER_API_TOKEN_V2_INACTIVE")
	accountToken := testSecrets.MustGetField("CLOUDFLARE_ACCOUNT_API_TOKEN_V2")
	accountID := testSecrets.MustGetField("CLOUDFLARE_ACCOUNT_API_TOKEN_V2_ACCOUNT_ID")
	accountTokenInactive := testSecrets.MustGetField("CLOUDFLARE_ACCOUNT_API_TOKEN_V2_INACTIVE")

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
			name: "cfut_ found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("cloudflare token %s", userToken)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "cfut_ found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("cloudflare token %s", userTokenInactive)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "cfat_ found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("cloudflare token %s account %s", accountToken, accountID)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "cfat_ found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("cloudflare token %s account %s", accountTokenInactive, accountID)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_CloudflareApiToken,
					Verified:     false,
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
				t.Errorf("CloudflareApiTokenV2.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
				got[i].RawV2 = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("CloudflareApiTokenV2.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
