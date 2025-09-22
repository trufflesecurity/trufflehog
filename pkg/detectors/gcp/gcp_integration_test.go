//go:build detectors
// +build detectors

package gcp

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

func TestGCP_FromChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("GCP_SECRET")
	secretInactive := testSecrets.MustGetField("GCP_INACTIVE")
	secretDisabled := testSecrets.MustGetField("GCP_DISABLED")

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
					Redacted:     "detector-tester@thog-sandbox.iam.gserviceaccount.com",
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/gcp/",
						"project":        "thog-sandbox",
						"private_key_id": "a7c42dc3272c5462d1c1b5f7aadfe7ff1eecc87b",
					},
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
					Redacted:     "detector-tester@thog-sandbox.iam.gserviceaccount.com",
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/gcp/",
						"project":        "thog-sandbox",
						"private_key_id": "a7c42dc3272c5462d1c1b5f7aadfe7ff1eecc87b",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "found, disabled",
			s:    Scanner{},
			args: args{
				ctx:    context.Background(),
				data:   []byte(fmt.Sprintf("You can find a gcp secret %s within", secretDisabled)),
				verify: true,
			},
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_GCP,
					Verified:     false,
					Redacted:     "detector-test@trufflehog-testing.iam.gserviceaccount.com",
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/gcp/",
						"project":        "trufflehog-testing",
						"private_key_id": "95cf38cc5e63007aa066e8a710fc64c3554d77f4",
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
			ignoreOpts := cmpopts.IgnoreFields(detectors.Result{}, "Raw", "RawV2", "verificationError", "AnalysisInfo")
			ignoreUnexported := cmpopts.IgnoreUnexported(detectors.Result{})
			if diff := cmp.Diff(got, tt.want, ignoreOpts, ignoreUnexported); diff != "" {
				t.Errorf("GCP.FromData() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

// TestGCP_KeyIDPopulation tests that the private_key_id is properly populated
// in ExtraData, either from the x509 endpoint (when available) or falling back
// to the embedded value in the JSON.
func TestGCP_KeyIDPopulation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors5")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}
	secret := testSecrets.MustGetField("GCP_SECRET")

	s := Scanner{}
	results, err := s.FromData(ctx, true, []byte(secret))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	// Verify that private_key_id is populated in ExtraData
	privateKeyID, exists := result.ExtraData["private_key_id"]
	if !exists {
		t.Error("private_key_id not found in ExtraData")
	}

	// Since the test service account is disabled (detector-test@trufflehog-testing),
	// the x509 endpoint returns 404, so we expect fallback to the embedded private_key_id from the JSON
	if privateKeyID == "" {
		t.Error("private_key_id should not be empty")
	}

	// Verify it's a reasonable key ID format (hex string)
	if len(privateKeyID) < 20 { // typical GCP key IDs are 40 char hex
		t.Errorf("private_key_id '%s' seems too short for a typical GCP key ID", privateKeyID)
	}

	t.Logf("private_key_id populated as: %s (fallback from embedded JSON due to disabled service account)", privateKeyID)
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
