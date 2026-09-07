//go:build detectors
// +build detectors

package humioingesttoken

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// newTestScanner returns a Scanner with the cloud endpoint configured, mirroring
// what DefaultDetectors() does at startup. Without this, Endpoints() returns
// nothing and the verification loop never runs.
func newTestScanner(client *http.Client) Scanner {
	s := Scanner{client: client}
	s.SetCloudEndpoint("https://cloud.us.humio.com")
	s.UseCloudEndpoint(true)
	return s
}

func TestHumioIngestToken_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors7")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("HUMIOINGESTTOKEN")
	inactiveSecret := testSecrets.MustGetField("HUMIOINGESTTOKEN_INACTIVE")

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
			s:    newTestScanner(nil),
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a humio ingest token %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_HumioIngestToken,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, real secrets, verification error due to timeout",
			s:    newTestScanner(common.SaneHttpClientTimeOut(1 * time.Microsecond)),
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a humio ingest token %s within", secret)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detector_typepb.DetectorType_HumioIngestToken,
					Verified:     false,
				}
				r.SetVerificationError(context.DeadlineExceeded)
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
		{
			name: "found, real secrets, verification error due to unexpected api surface",
			s:    newTestScanner(common.ConstantResponseHttpClient(500, "{}")),
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a humio ingest token %s within", secret)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detector_typepb.DetectorType_HumioIngestToken,
					Verified:     false,
				}
				r.SetVerificationError(fmt.Errorf("unexpected HTTP response status 500"))
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    newTestScanner(nil),
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a humio ingest token %s within but not valid", inactiveSecret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_HumioIngestToken,
					Verified:     false,
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			s:    newTestScanner(nil),
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
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("HumioIngestToken.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError", "SecretParts", "ExtraData")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("HumioIngestToken.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
