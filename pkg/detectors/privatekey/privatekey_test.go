//go:build detectors
// +build detectors

package privatekey

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestPrivatekey_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretTLS := testSecrets.MustGetField("PRIVATEKEY_TLS")
	secretGitHub := testSecrets.MustGetField("PRIVATEKEY_GITHUB")
	secretInactive := testSecrets.MustGetField("PRIVATEKEY_UNVERIFIED")
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
			name: "found, unverified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find privatekey secret %s within", secretInactive)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     false,
					Redacted:     "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYw",
				},
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     false,
					Redacted:     "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgw",
				},
			},
			wantErr: false,
		},
		{
			name: "found TLS private key, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(secretTLS),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     true,
					Redacted:     "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgw",
					StructuredData: &detectorspb.StructuredData{
						TlsPrivateKey: []*detectorspb.TlsPrivateKey{
							{
								CertificateFingerprint: "1e20c40deb44a8539dd3ac3e8c53b72750cb19f9",
								VerificationUrl:        "https://crt.sh/?q=1e20c40deb44a8539dd3ac3e8c53b72750cb19f9",
								ExpirationTimestamp:    1497337731,
							},
							{
								CertificateFingerprint: "0e9de31fb2ee16465a4d5d93b227d54f870326d1",
								VerificationUrl:        "https://crt.sh/?q=0e9de31fb2ee16465a4d5d93b227d54f870326d1",
								ExpirationTimestamp:    1528192832,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found GitHub SSH private key, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(secretGitHub),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     true,
					Redacted:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5v",
					StructuredData: &detectorspb.StructuredData{
						GithubSshKey: []*detectorspb.GitHubSSHKey{
							{
								User: "thisisforgithub0",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found encrypted GitHub SSH private key, verified",
			s:    Scanner{},
			args: args{
				ctx: context.Background(),
				data: []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
						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
						Hx7UPVlTK8dyvk1Z+Yw0nrfNClI=
						-----END OPENSSH PRIVATE KEY-----
		`),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     true,
					Redacted:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFl",
					StructuredData: &detectorspb.StructuredData{
						GithubSshKey: []*detectorspb.GitHubSSHKey{
							{
								User: "thisisforgithub0",
							},
						},
					},
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
			s := Scanner{IncludeExpired: true}
			got, err := s.FromData(tt.args.ctx, tt.args.verify, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivatekeyCI.FromData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if os.Getenv("FORCE_PASS_DIFF") == "true" {
				return
			}
			for i := range got {
				if len(got[i].Raw) == 0 {
					t.Fatal("no raw secret present")
				}
				got[i].Raw = nil
			}
			if diff := pretty.Compare(got, tt.want); diff != "" {
				t.Errorf("PrivatekeyCI.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
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

func Test_lookupFingerprint(t *testing.T) {
	tests := []struct {
		name                      string
		publicKeyFingerprintInHex string
		wantFingerprints          bool
		wantErr                   bool
		includeExpired            bool
	}{
		{
			name:                      "got some",
			publicKeyFingerprintInHex: "4c5da06caa1c81df9c8e1abe43bac385de1bda76",
			wantFingerprints:          true,
			wantErr:                   false,
			includeExpired:            true,
		},
		{
			name:                      "got some",
			publicKeyFingerprintInHex: "none",
			wantFingerprints:          false,
			wantErr:                   false,
			includeExpired:            true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFingerprints, err := lookupFingerprint(tt.publicKeyFingerprintInHex, tt.includeExpired)
			if (err != nil) != tt.wantErr {
				t.Errorf("lookupFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFingerprints != nil && len(gotFingerprints.TlsPrivateKey) > 0, tt.wantFingerprints) {
				t.Errorf("lookupFingerprint() = %v, want %v", gotFingerprints, tt.wantFingerprints)
			}
		})
	}
}
