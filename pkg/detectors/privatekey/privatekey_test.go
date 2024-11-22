//go:build detectors
// +build detectors

package privatekey

import (
	"context"
	"fmt"
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
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secretTLS := testSecrets.MustGetField("PRIVATEKEY_TLS")
	secretGitHub := testSecrets.MustGetField("PRIVATEKEY_GITHUB")
	secretGitHubEncrypted := testSecrets.MustGetField("PRIVATEKEY_GITHUB_ENCRYPTED")
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
					ExtraData: map[string]string{
						"certificate_urls": "https://crt.sh/?q=1e20c40deb44a8539dd3ac3e8c53b72750cb19f9, https://crt.sh/?q=0e9de31fb2ee16465a4d5d93b227d54f870326d1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found encrypted GitHub SSH private key, verified",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(secretGitHubEncrypted),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_PrivateKey,
					Verified:     true,
					Redacted:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFl",
					ExtraData: map[string]string{
						"github_user":                   "sirdetectsalot",
						"encrypted":                     "true",
						"cracked_encryption_passphrase": "true",
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
			gotFingerprints, err := lookupFingerprint(context.TODO(), tt.publicKeyFingerprintInHex, tt.includeExpired)
			if (err != nil) != tt.wantErr {
				t.Errorf("lookupFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(len(gotFingerprints.CertificateURLs) > 0, tt.wantFingerprints) {
				t.Errorf("lookupFingerprint() = %v, want %v", gotFingerprints, tt.wantFingerprints)
			}
		})
	}
}

func TestResult_GetExtraData(t *testing.T) {
	tests := []struct {
		name   string
		result result
		want   map[string]string
	}{
		{
			name: "no certificate URLs or results",
			result: result{
				CertificateURLs: []string{},
				driftwoodResult: driftwoodResult{
					CertificateResults: []certificateResult{},
				},
			},
			want: map[string]string{},
		},
		{
			name: "with certificate URLs",
			result: result{
				CertificateURLs: []string{"https://crt.sh/?q=1e20c40deb44a8539dd3ac3e8c53b72750cb19f9"},
				driftwoodResult: driftwoodResult{
					CertificateResults: []certificateResult{},
				},
			},
			want: map[string]string{
				"certificate_urls": "https://crt.sh/?q=1e20c40deb44a8539dd3ac3e8c53b72750cb19f9",
			},
		},
		{
			name: "with certificate results",
			result: result{
				CertificateURLs: []string{},
				driftwoodResult: driftwoodResult{
					CertificateResults: []certificateResult{
						{
							Domains:                []string{"example.com"},
							CertificateFingerprint: "1e20c40deb44a8539dd3ac3e8c53b72750cb19f9",
							ExpirationTimestamp:    time.Date(2023, time.December, 31, 23, 59, 59, 0, time.UTC),
							IssuerName:             "Example CA",
							SubjectName:            "example.com",
							IssuerOrganization:     []string{"Example Org"},
							SubjectOrganization:    []string{"Example Org"},
							KeyUsages:              []string{"DigitalSignature", "KeyEncipherment"},
							ExtendedKeyUsages:      []string{"ServerAuth", "ClientAuth"},
							SubjectKeyID:           "abcdef123456",
							AuthorityKeyID:         "123456abcdef",
							SerialNumber:           "123456",
						},
					},
				},
			},
			want: map[string]string{
				"domains":                 "example.com",
				"certificate_fingerprint": "1e20c40deb44a8539dd3ac3e8c53b72750cb19f9",
				"expiration_timestamp":    "2023-12-31 23:59:59 +0000 UTC",
				"issuer_name":             "Example CA",
				"subject_name":            "example.com",
				"issuer_organization":     "Example Org",
				"subject_organization":    "Example Org",
				"key_usages":              "DigitalSignature,KeyEncipherment",
				"extended_key_usages":     "ServerAuth,ClientAuth",
				"subject_key_id":          "abcdef123456",
				"authority_key_id":        "123456abcdef",
				"serial_number":           "123456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := pretty.Compare(tt.result.GetExtraData(), tt.want); diff != "" {
				t.Errorf("GetExtraData() diff (-got +want):\n%s", diff)
			}
		})
	}
}
