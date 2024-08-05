//go:build detectors
// +build detectors

package gcp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestGCP_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "normal file",
			input: `{
  "type": "service_account",
  "project_id": "api-5153635936162123384-123456",
  "private_key_id": "2b387b72ec1b082aa7e52189d9c43f58fb19fb48",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE/XlaMP419pkUEXAMPLE=\n-----END PRIVATE KEY-----\n",
  "client_email": "unit-test-value@api-5153635936162123384-123456.iam.gserviceaccount.com",
  "client_id": "109763165530299657612",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/unit-test-value%40api-5153635936162123384-123456.iam.gserviceaccount.com"
}`,
			want: []string{"{\"type\":\"service_account\",\"project_id\":\"api-5153635936162123384-123456\",\"private_key_id\":\"2b387b72ec1b082aa7e52189d9c43f58fb19fb48\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE/XlaMP419pkUEXAMPLE=\\n-----END PRIVATE KEY-----\\n\",\"client_email\":\"unit-test-value@api-5153635936162123384-123456.iam.gserviceaccount.com\",\"client_id\":\"109763165530299657612\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\",\"client_x509_cert_url\":\"https://www.googleapis.com/robot/v1/metadata/x509/unit-test-value%40api-5153635936162123384-123456.iam.gserviceaccount.com\"}"},
		},
		{
			name:  "escaped JSON",
			input: `{"credentials":"{\n  \"type\": \"service_account\",\n  \"project_id\": \"unit-test\",\n  \"private_key_id\": \"10f922eb17fba903dc59f7baf753976233520012\",\n  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCgyAZHbtJu1MRf\\ng9+Wg==\\n-----END PRIVATE KEY-----\\n\",\n  \"client_email\": \"fake-value@unit-test.iam.gserviceaccount.com\",\n  \"client_id\": \"123456476766156356779\",\n  \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n  \"token_uri\": \"https://oauth2.googleapis.com/token\",\n  \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n  \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/fake-value%40unit-test.iam.gserviceaccount.com\"\n}\n"}`,
			want:  []string{"{\"type\":\"service_account\",\"project_id\":\"unit-test\",\"private_key_id\":\"10f922eb17fba903dc59f7baf753976233520012\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCgyAZHbtJu1MRf\\ng9+Wg==\\n-----END PRIVATE KEY-----\\n\",\"client_email\":\"fake-value@unit-test.iam.gserviceaccount.com\",\"client_id\":\"123456476766156356779\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\",\"client_x509_cert_url\":\"https://www.googleapis.com/robot/v1/metadata/x509/fake-value%40unit-test.iam.gserviceaccount.com\"}g"},
		},
		// TODO: Create an example of these.
		//{
		//	name:  "Slack mangled email",
		//	input: ``,
		//	want:  []string{""},
		//},
		//{
		//	name:  "Empty client email",
		//	input: ``,
		//	want:  []string{""},
		//},
		//{
		//	name:  "Carets",
		//	input: ``,
		//	want:  []string{""},
		//},
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

func TestGCP_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("GCP_SECRET")
	secretInactive := testSecrets.MustGetField("GCP_INACTIVE")
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
				data:   []byte(fmt.Sprintf("You can find a gcp secret %s within", secret)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_GCP,
					Verified:     true,
					Redacted:     "secret-scanner-test-account@thog-sandbox.iam.gserviceaccount.com",
				},
			},
			wantErr: false,
		},
		{
			name: "found, not verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a gcp secret %s within", secretInactive)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_GCP,
					Verified:     false,
					Redacted:     "secretcom",
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
				t.Errorf("GCP.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("GCP.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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
