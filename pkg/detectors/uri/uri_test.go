package uri

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestURI_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("URI_SECRET")
	secretInactive := testSecrets.MustGetField("URI_INACTIVE")
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
			name: "found, unverified, wrong username",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a uri secret %s within", secretInactive)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_URI,
					Verified:     false,
					Redacted:     "https://user:**********@www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx",
				},
			},
			wantErr: false,
		},
		{
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a uri secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_URI,
					Verified:     true,
					Redacted:     "https://httpwatch:**********@www.httpwatch.com/httpgallery/authentication/authenticatedimage/default.aspx",
				},
			},
			wantErr: false,
		},
		{
			name: "bad proto",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte("file://user:pass@foo.com:123/wh/at/ever"),
				verify: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{allowKnownTestSites: true}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("URI.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if os.Getenv("FORCE_PASS_DIFF") == "true" {
			// 	return
			// }
			for i := range got {
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("URI.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
				_, err := s.FromData(ctx, false, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
