//go:build detectors
// +build detectors

package bitbucketapppassword

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func TestBitbucketAppPassword_FromData_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors2")
	if err != nil {
		t.Fatalf("could not get test secrets from GCP: %s", err)
	}

	username := testSecrets.MustGetField("USERNAME")
	validPassword := testSecrets.MustGetField("BITBUCKETAPPPASSWORD")
	invalidPassword := "ATBB123abcDEF456ghiJKL789mnoPQR" // An invalid but correctly formatted password

	tests := []struct {
		name    string
		input   string
		want    []detectors.Result
		wantErr bool
	}{
		{
			name:  "valid credential",
			input: fmt.Sprintf("https://%s:%s@bitbucket.org", username, validPassword),
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BitbucketAppPassword,
					Verified:     true,
					Raw:          []byte(fmt.Sprintf("%s:%s", username, validPassword)),
				},
			},
		},
		{
			name:  "invalid credential",
			input: fmt.Sprintf("https://%s:%s@bitbucket.org", username, invalidPassword),
			want: []detectors.Result{
				{
					DetectorType: detectorspb.DetectorType_BitbucketAppPassword,
					Verified:     false,
					Raw:          []byte(fmt.Sprintf("%s:%s", username, invalidPassword)),
				},
			},
		},
		{
			name:  "no credential found",
			input: "this string has no credentials",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Scanner{}
			got, err := s.FromData(ctx, true, []byte(tc.input))

			if (err != nil) != tc.wantErr {
				t.Fatalf("FromData() error = %v, wantErr %v", err, tc.wantErr)
			}
			// Normalizing results for comparison by removing fields that are not relevant for the test
			for i := range got {
				if got[i].VerificationError() != nil {
					t.Logf("verification error: %s", got[i].VerificationError())
				}
			}

			if diff := cmp.Diff(tc.want, got, cmp.Comparer(func(x, y detectors.Result) bool {
				return x.Verified == y.Verified && string(x.Raw) == string(y.Raw) && x.DetectorType == y.DetectorType
			})); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func BenchmarkFromData(benchmark *testing.B) {
	ctx := context.Background()
	s := &Scanner{}
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
