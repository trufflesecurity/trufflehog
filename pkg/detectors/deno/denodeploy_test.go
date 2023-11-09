//go:build detectors
// +build detectors

package denodeploy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestDenoDeploy_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		{
			name: `valid_deployctl`,
			data: `  "tasks": {
  	"d": "deployctl deploy --prod --import-map=import_map.json --project=o88 main.ts --token ddp_eg5DjUmbR5lHZ3LiN9MajMk2tA1GxL2NRdvc",
    "start": "deno run -A --unstable --watch=static/,routes/ dev.ts"
  },`,
			shouldMatch: true,
			match:       `ddp_eg5DjUmbR5lHZ3LiN9MajMk2tA1GxL2NRdvc`,
		},
		{
			name:        `valid_dotenv`,
			data:        `DENO_KV_ACCESS_TOKEN=ddp_hn029Cl2dIN4Jb0BF0L1V9opokoPVC30ddGk`,
			shouldMatch: true,
			match:       `ddp_hn029Cl2dIN4Jb0BF0L1V9opokoPVC30ddGk`,
		},
		{
			name: `valid_dotfile`,
			data: `# deno
export DENO_INSTALL="/home/khushal/.deno"
export PATH="$DENO_INSTALL/bin:$PATH"
export DENO_DEPLOY_TOKEN="ddp_QLbDfRlMKpXSf3oCz20Hp8wVVxThDwlwhFbV""`,
			shouldMatch: true,
			match:       `ddp_QLbDfRlMKpXSf3oCz20Hp8wVVxThDwlwhFbV`,
		},
		{
			name:        `valid_webtoken`,
			data:        `    //     headers: { Authorization: 'Bearer ddw_ebahKKeZqiZVXOad7KJRHskLeP79Lf0OJXlj' }`,
			shouldMatch: true,
			match:       `ddw_ebahKKeZqiZVXOad7KJRHskLeP79Lf0OJXlj`,
		},

		// False positives
		{
			name: `invalid_token1`,
			data: `                "summoner2Id": 4,
                "summonerId": "oljqJ1Ddp_LJm5s6ONPAJXIl97Bi6pcKMywYLG496a58rA",
                "summonerLevel": 146,`,
			shouldMatch: false,
		},
		{
			name:        `invalid_token2`,
			data:        `        "image_thumbnail_url": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQFq6zzTXpXtRDdP_JbNkS58loAyCvhhZ1WWONaUkJoWbHsgwIJBw",`,
			shouldMatch: false,
		},
		{
			name:        `invalid_token3`,
			data:        `matplotlib/backends/_macosx.cpython-37m-darwin.so,sha256=DDw_KRE5yTUEY5iDBwBW7KvDcTkDmrIu0N18i8I3FvA,90140`,
			shouldMatch: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("DenoDeploy.FromData() error = %v", err)
				return
			}

			if test.shouldMatch {
				if len(results) == 0 {
					t.Errorf("%s: did not receive a match for '%v' when one was expected", test.name, test.data)
					return
				}
				expected := test.data
				if test.match != "" {
					expected = test.match
				}
				result := results[0]
				resultData := string(result.Raw)
				if resultData != expected {
					t.Errorf("%s: did not receive expected match.\n\texpected: '%s'\n\t  actual: '%s'", test.name, expected, resultData)
					return
				}
			} else {
				if len(results) > 0 {
					t.Errorf("%s: received a match for '%v' when one wasn't wanted", test.name, test.data)
					return
				}
			}
		})
	}
}

func TestDenoDeploy_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("DENODEPLOY")
	inactiveSecret := testSecrets.MustGetField("DENODEPLOY_INACTIVE")

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
			name: "found, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a denodeploy secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DenoDeploy,
					Verified:     true,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a denodeploy secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DenoDeploy,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: false,
		},
		{
			name: "not found",
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
		{
			name: "found, would be verified if not for timeout",
			s:    Scanner{client: common.SaneHttpClientTimeOut(1 * time.Microsecond)},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a denodeploy secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DenoDeploy,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
		{
			name: "found, verified but unexpected api surface",
			s:    Scanner{client: common.ConstantResponseHttpClient(404, "")},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a denodeploy secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_DenoDeploy,
					Verified:     false,
				},
			},
			wantErr:             false,
			wantVerificationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Denodeploy.FromData() error = %v, wantErr %v", err, tt.wantErr)
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "verificationError", "ExtraData")
			if diff := cmp.Diff(got, tt.want, ignoreOpts); diff != "" {
				t.Errorf("Denodeploy.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
