//go:build detectors
// +build detectors

package mailgun

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestMailgun_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("MAILGUN_TOKEN")
	inactiveSecret := testSecrets.MustGetField("MAILGUN_INACTIVE")
	keyDashSecret := testSecrets.MustGetField("NEW_MAILGUN_TOKEN_ACTIVE")
	inactiveHexEncodedSecret := testSecrets.MustGetField("NEW_MAILGUN_TOKEN_INACTIVE")

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
				data:   []byte(fmt.Sprintf("You can find a mailgun secret %s within https://api.mailgun.net/v3/domains", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Mailgun,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, verified key-dash mailgun pattern token",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a mailgun secret %s within https://api.mailgun.net/v3/domains", keyDashSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Mailgun,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified key-dash mailgun pattern token",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a mailgun secret %s within https://api.mailgun.net/v3/domains", inactiveHexEncodedSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Mailgun,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a mailgun secret %s within but unverified", inactiveSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Mailgun,
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
				t.Errorf("Mailgun.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
				got[i].AnalysisInfo = nil
				got[i].ExtraData = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Mailgun.FromData() %s  diff: (-got +want)\n%s", tt.name, diff)
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
