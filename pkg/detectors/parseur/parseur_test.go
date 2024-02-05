package parseur

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

func TestParseur_Pattern(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		shouldMatch bool
		match       string
	}{
		// True positives
		{
			name:        "valid",
			data:        `const parseurToken = "6813a07afc6b4ed35518635c6fb70abf4e721962";`,
			shouldMatch: true,
			match:       "6813a07afc6b4ed35518635c6fb70abf4e721962",
		},
		// This technically isn't valid but shouldn't be excluded based on the current pattern.
		{
			name: "valid",
			data: `commit 6813a07afc6b4ed35518635c6fb70abf4e721962
Author: Stéphane Borel <stef@videolan.org>
Date:   Thu Dec 30 13:59:59 1999 +0000

    * Modifications de quelques erreurs sur le parseur

commit 2c65bd981d308d264aa0c07083b2bc914905deb3`,
			shouldMatch: true,
			match:       "2c65bd981d308d264aa0c07083b2bc914905deb3",
		},

		// False positives
		{
			name: `invalid_parseuri_package.json`,
			data: `{
  "dist": {
    "shasum": "80204a50d4dbb779bfdc6ebe2778d90e4bce320a",
    "tarball": "https://registry.npmjs.org/parseuri/-/parseuri-0.0.5.tgz"
  },
  "gitHead": "792c9a63162a4484eb6b4f95fc611ccf224a24b6",`,
			shouldMatch: false,
		},
		// https://github.com/airalab/airapkgs/blob/cb3f8021303f79345f65b5328b75117044bde852/pkgs/servers/mesh/meshviewer/yarn.nix#L6066
		{
			name: `invalid_parseuri_nix`,
			data: `
    {
      name = "parseuri-0.0.5.tgz";
      path = fetchurl {
        name = "parseuri-0.0.5.tgz";
        url  = "https://registry.yarnpkg.com/parseuri/-/parseuri-0.0.5.tgz";
        sha1 = "80204a50d4dbb779bfdc6ebe2778d90e4bce320a";
      };
    }`,
			shouldMatch: false,
		},
		{
			name: `invalid_parseurl_yarn`,
			data: `parseurl@~1.3.1:
  version "1.3.1"
  resolved "https://registry.yarnpkg.com/parseurl/-/parseurl-1.3.1.tgz#c8ab8c9223ba34888aa64a297b28853bec18da56"`,
			shouldMatch: false,
		},
		// https://github.com/tolerious/django-wechat/blob/18f3f2d5d8377c7dde8700afc5977861c8488b68/django_weixin/Sample.py#L30
		{
			name: `invalid_parseurl_func`,
			data: `#sVerifyMsgSig=HttpUtils.ParseUrl("msg_signature")
   sVerifyMsgSig="5c45ff5e21c57e6ad56bac8758b79b1d9ac89fd3"`,
			shouldMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}

			results, err := s.FromData(context.Background(), false, []byte(test.data))
			if err != nil {
				t.Errorf("Parseur.FromData() error = %v", err)
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

func TestParseur_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors3")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("PARSEUR")
	inactiveSecret := testSecrets.MustGetField("PARSEUR_INACTIVE")

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
				data:   []byte(fmt.Sprintf("You can find a parseur secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Parseur,
					Verified:     true,
				},
			},
			wantErr: false,
		},
		{
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a parseur secret %s within but not valid", inactiveSecret)), // the secret would satisfy the regex but not pass validation
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_Parseur,
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
				t.Errorf("Parseur.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatalf("no raw secret present: \n %+v", got[i])
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("Parseur.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
