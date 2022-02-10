package aws

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestScanner_FromChunk(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "scanners2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("AWS_SECRET")
	secretInactive := testSecrets.MustGetField("AWS_INACTIVE")
	id := testSecrets.MustGetField("AWS")

	type args struct {
		ctx    context.Context
		data   []byte
		verify bool
	}
	tests := []struct {
		name        string
		args        args
		wantSecrets []detectors.Result
		wantErr     bool
	}{
		{
			name: "live key",
			args: args{
				ctx:  ctx,
				data: []byte(fmt.Sprintf("You can find a aws secret %s within awsId %s", secret, id)),

				verify: true,
			},
			wantSecrets: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_AWS,
					Verified:     true,
					Redacted:     id,
				},
			},
			wantErr: false,
		},
		{
			name: "dead key",
			args: args{
				ctx:    ctx,
				data:   []byte(fmt.Sprintf("You can find a aws secret %s within awsId %s", secretInactive, id)),
				verify: true,
			},
			wantSecrets: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_AWS,
					Verified:     false,
					Redacted:     id,
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			args: args{
				ctx:    ctx,
				data:   []byte("You cannot find the secret within"),
				verify: true,
			},
			wantSecrets: nil,
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Scanner.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.wantSecrets); diff != "" {
				t.Errorf("%s: Scanner.FromData() diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := Scanner{}
	for name, data := range detectors.MustGetBenchmarkData() {
		benchmark.Run(name, func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				s.FromData(ctx, false, data)
			}
		})
	}
}

func Test_callerIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "scanners2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("AWS_SECRET")
	secretInactive := testSecrets.MustGetField("AWS_INACTIVE")
	id := testSecrets.MustGetField("AWS")

	type args struct {
		key    string
		secret string
		ctx    context.Context
	}
	tests := []struct {
		name    string
		args    args
		want    *sts.GetCallerIdentityOutput
		wantErr bool
	}{
		{
			name: "invalid",
			args: args{
				key:    id,
				secret: secretInactive,
				ctx:    context.Background(),
			},
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				key:    id,
				secret: secret,
				ctx:    context.Background(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := callerIdentity(tt.args.ctx, tt.args.key, tt.args.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("callerIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
