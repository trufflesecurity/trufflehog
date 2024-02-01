//go:build detectors
// +build detectors

package browserstack

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

func TestBrowserStack_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors3")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretUser := testSecrets.MustGetField("BROWSERSTACK_USER")
	secret := testSecrets.MustGetField("BROWSERSTACK")
	inactiveSecret := testSecrets.MustGetField("BROWSERSTACK_INACTIVE")

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
				data:   []byte(fmt.Sprintf("You can find a BROWSERSTACK_ACCESS_KEY %s within BROWSERSTACK_USERNAME %s", secret, secretUser)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BrowserStack,
					Verified:     true,
					RawV2:        []byte(fmt.Sprintf("%s%s", secret, secretUser)),
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a BROWSERSTACK_ACCESS_KEY %s within BROWSERSTACK_USERNAME %s but not valid", inactiveSecret, secretUser)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BrowserStack,
					Verified:     false,
					RawV2:        []byte(fmt.Sprintf("%s%s", inactiveSecret, secretUser)),
				},
			},
			wantErr: false,
		},
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a BROWSERSTACK_ACCESS_KEY %s within BROWSERSTACK_USERNAME %s", secret, secretUser)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_BrowserStack,
					RawV2:        []byte(fmt.Sprintf("%s%s", secret, secretUser)),
					Verified:     false,
				}
				r.SetVerificationError(fmt.Errorf("context deadline exceeded"), secret)
				results := []detectors.Result{r}
				return results
			}(),
			wantErr: false,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a BROWSERSTACK_ACCESS_KEY %s within BROWSERSTACK_USERNAME %s", secret, secretUser)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_BrowserStack,
					Verified:     false,
					RawV2:        []byte(fmt.Sprintf("%s%s", secret, secretUser)),
				}
				r.SetVerificationError(fmt.Errorf("unexpected HTTP response status 404"), secret)
				results := []detectors.Result{r}
				return results
			}(),
			wantErr: false,
		},
		{
			name: "found, verified but blocked by browserstack",
			s:    Scanner{client: common.SaneHttpClient()},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a BROWSERSTACK_ACCESS_KEY %s within BROWSERSTACK_USERNAME %s", secret, secretUser)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_BrowserStack,
					Verified:     false,
					RawV2:        []byte(fmt.Sprintf("%s%s", secret, secretUser)),
				}
				r.SetVerificationError(fmt.Errorf("blocked by browserstack"), secret)
				results := []detectors.Result{r}
				return results
			}(),
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
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("BrowserStack.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("BrowserStack.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
