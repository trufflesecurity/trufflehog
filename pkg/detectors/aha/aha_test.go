//go:build detectors
// +build detectors

package aha

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestAha_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: "aha.io = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff/example.aha.io'",
			want:  []string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
		},
		{
			name:  "valid pattern - detect URL far away from keyword",
			input: "aha.io = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n URL is not close to the keyword but should be detected example.aha.io'",
			want:  []string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: "aha.io keyword is not close to the real key and secret = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff/example.aha.io'",
			want:  nil,
		},
		{
			name:  "valid pattern - only key",
			input: "aha.io 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			want:  []string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
		},
		{
			name:  "valid pattern - only URL",
			input: "aha.io example.aha.io",
			want:  nil,
		},
		{
			name:  "invalid pattern",
			input: "aha.io 00112233445566778899aabbCC$%eeff00112233445566778899aabbccddeeff/example.fake.io",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestAha_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	domain := testSecrets.MustGetField("AHA_DOMAIN")
	secret := testSecrets.MustGetField("AHA_SECRET")
	inactiveSecret := testSecrets.MustGetField("AHA_INACTIVE")

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
			s:    Scanner{client: common.ConstantResponseHttpClient(200, "{}")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a aha secret %s within %s but verified", secret, domain)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Aha,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, real secrets, verification error due to timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a aha secret %s within %s but verified", secret, domain)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_Aha,
					Verified:     false,
				}
				r.SetVerificationError(context.DeadlineExceeded)
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
		{
			name: "found, real secrets, verification error due to unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(500, "{}")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a aha secret %s within %s but verified", secret, domain)),
				verify: true,
			},
			want: func() []detectors.Result {
				r := detectors.Result{
					DetectorType: detectorspb.DetectorType_Aha,
					Verified:     false,
				}
				r.SetVerificationError(fmt.Errorf("unexpected HTTP response status 500"))
				return []detectors.Result{r}
			}(),
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a aha secret %s within but not valid domain %s", inactiveSecret, domain)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Aha,
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
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Aha.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Aha.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
