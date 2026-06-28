package tencentcloud

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	// Split the prefix so the literal does not match secret-scanning patterns; the
	// runtime value is a well-formed SecretId that exercises the detector regex.
	testSecretID  = "AKID" + "EXAMPLE0EXAMPLE1EXAMPLE2EXAMPLE3"
	testSecretKey = "7pQ2mX9kZ4vL8nR3tB6yW1cF5jH0dS2a"
)

func TestTencentCloud_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - assignment",
			input: `TENCENTCLOUD_SECRET_ID=` + testSecretID + `\nTENCENTCLOUD_SECRET_KEY=` + testSecretKey,
			want:  []string{testSecretID + ":" + testSecretKey},
		},
		{
			name:  "valid pattern - quoted",
			input: `secret_id: "` + testSecretID + `", secret_key: "` + testSecretKey + `"`,
			want:  []string{testSecretID + ":" + testSecretKey},
		},
		{
			name:  "invalid pattern - secret key without secret id",
			input: `TENCENTCLOUD_SECRET_KEY=` + testSecretKey,
			want:  nil,
		},
		{
			name:  "invalid pattern - secret id without secret key",
			input: `TENCENTCLOUD_SECRET_ID=` + testSecretID,
			want:  nil,
		},
		{
			name:  "invalid pattern - malformed secret id prefix",
			input: `secret_id = BKIDEXAMPLE0EXAMPLE1EXAMPLE2EXAMPLE3, secret_key = ` + testSecretKey,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && test.want != nil {
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
				actual[string(r.RawV2)] = struct{}{}
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

// TestTencentCloud_Verification exercises the verification logic using mock HTTP
// clients, so it requires no live credentials.
func TestTencentCloud_Verification(t *testing.T) {
	input := []byte("secret_id = " + testSecretID + ", secret_key = " + testSecretKey)

	tests := []struct {
		name                string
		client              *http.Client
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:         "verified (200 + region set body)",
			client:       common.ConstantResponseHttpClient(http.StatusOK, `{"Response":{"TotalCount":1,"RegionSet":[{"Region":"ap-guangzhou"}],"RequestId":"abc"}}`),
			wantVerified: true,
		},
		{
			name:         "unverified - determinate (signature failure)",
			client:       common.ConstantResponseHttpClient(http.StatusOK, `{"Response":{"Error":{"Code":"AuthFailure.SignatureFailure","Message":"signature mismatch"},"RequestId":"abc"}}`),
			wantVerified: false,
		},
		{
			name:         "unverified - determinate (secret id not found)",
			client:       common.ConstantResponseHttpClient(http.StatusOK, `{"Response":{"Error":{"Code":"AuthFailure.SecretIdNotFound","Message":"not found"},"RequestId":"abc"}}`),
			wantVerified: false,
		},
		{
			name:                "unverified - indeterminate (unexpected error code)",
			client:              common.ConstantResponseHttpClient(http.StatusOK, `{"Response":{"Error":{"Code":"InternalError","Message":"server error"},"RequestId":"abc"}}`),
			wantVerified:        false,
			wantVerificationErr: true,
		},
		{
			name:                "unverified - indeterminate (unexpected status)",
			client:              common.ConstantResponseHttpClient(http.StatusInternalServerError, ""),
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: test.client}
			results, err := s.FromData(context.Background(), true, input)
			if err != nil {
				t.Fatalf("FromData() error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := results[0]
			if r.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
			}
			if (r.VerificationError() != nil) != test.wantVerificationErr {
				t.Errorf("VerificationError = %v, wantVerificationErr %v", r.VerificationError(), test.wantVerificationErr)
			}
		})
	}
}

// TestTencentCloud_Verification_Timeout covers the indeterminate failure caused
// by a network timeout. The 1ms client deadline elapses before the request to
// the Tencent Cloud API can complete, so verification must surface an
// indeterminate error.
func TestTencentCloud_Verification_Timeout(t *testing.T) {
	s := Scanner{client: common.SaneHttpClientTimeOut(1 * time.Millisecond)}

	results, err := s.FromData(context.Background(), true, []byte("secret_id = "+testSecretID+", secret_key = "+testSecretKey))
	if err != nil {
		t.Fatalf("FromData() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Errorf("expected unverified on timeout")
	}
	if results[0].VerificationError() == nil {
		t.Errorf("expected indeterminate verification error on timeout")
	}
}
