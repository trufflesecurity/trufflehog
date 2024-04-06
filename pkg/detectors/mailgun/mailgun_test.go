//go:build detectors
// +build detectors

package mailgun

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestMailgun_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// TODO: Confirm that this is actually an "original token".
		// It's just a hex token encoded as basic auth.
		{
			name: "original token",
			input: `- request:
    method: get
    uri: https://api.mailgun.net/v3/integration-test.domain.invalid/templates/test.template
    body:
      encoding: US-ASCII
      string: ''
    headers:
      Accept:
      - "*/*"
      User-Agent:
      - rest-client/2.1.0 (darwin21.6.0 x86_64) ruby/2.5.1p57
      Accept-Encoding:
      - gzip;q=1.0,deflate;q=0.6,identity;q=0.3
      Host:
      - api.mailgun.net
      Authorization:
      - Basic YXBpOmFjZWM0YzA1YjFmMmZjZWJjZmE4ZGE2NDVkYTEwMjMxLTQxM2UzNzNjLTBhYWQzYzM3`,
			want: []string{"YXBpOmFjZWM0YzA1YjFmMmZjZWJjZmE4ZGE2NDVkYTEwMjMxLTQxM2UzNzNjLTBhYWQzYzM3"},
		},
		{
			name: "key- token",
			input: `public static ClientResponse GetBounce() {
   Client client = new Client();
   client.addFilter(new HTTPBasicAuthFilter("api",
           "key-3ax63njp29jz6fds4gc373sgvjxteol1"));
   WebResource webResource =
       client.resource("https://api.mailgun.net/v2/samples.mailgun.org/" +
               "bounces/foo@bar.com");
   return webResource.get(ClientResponse.class);
}`,
			want: []string{"key-3ax63njp29jz6fds4gc373sgvjxteol1"},
		},
		{
			name:  "hex token",
			input: `curl -X POST https://api.mailgun.net/v3/DOMAIN.TEST/messages -u "api:e915b5cdb9a582685d8f3fb1bea0f20f-07bc7b05-f14816a1"`,
			want:  []string{"e915b5cdb9a582685d8f3fb1bea0f20f-07bc7b05-f14816a1"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chunkSpecificDetectors := make(map[ahocorasick.DetectorKey]detectors.Detector, 2)
			ahoCorasickCore.PopulateMatchingDetectors(test.input, chunkSpecificDetectors)
			if len(chunkSpecificDetectors) == 0 {
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
