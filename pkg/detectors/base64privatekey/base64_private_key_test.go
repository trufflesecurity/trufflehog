package base64privatekey

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestBase64PrivateKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	// Create test private keys and encode them
	rsaPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z6ca1yP6DGV/t5Z3i3h4z3Y8oHs5vZ0N2TQzL1d5dX5w3e
-----END RSA PRIVATE KEY-----`

	ecPrivateKey := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKj0p8D7bJxzd/h3h3h3h3h3h3h3h3h3h3h3h3h3h3
-----END EC PRIVATE KEY-----`

	validBase64RSA := base64.StdEncoding.EncodeToString([]byte(rsaPrivateKey))
	validBase64EC := base64.StdEncoding.EncodeToString([]byte(ecPrivateKey))

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid base64 RSA private key",
			input: `PRIVATE_KEY="` + validBase64RSA + `"`,
			want:  []string{validBase64RSA},
		},
		{
			name:  "valid base64 EC private key",
			input: `EC_KEY=` + validBase64EC,
			want:  []string{validBase64EC},
		},
		{
			name: "multiple base64 private keys",
			input: `
				RSA: ` + validBase64RSA + `
				EC: ` + validBase64EC,
			want: []string{validBase64RSA, validBase64EC},
		},
		{
			name:  "deduplication - repeated key",
			input: `PRIVATE_KEY=` + validBase64RSA + ` and PRIVATE_KEY=` + validBase64RSA,
			want:  []string{validBase64RSA},
		},
		{
			name:  "invalid - not base64",
			input: `PRIVATE_KEY="not_valid_base64!!!"`,
			want:  nil,
		},
		{
			name:  "invalid - base64 but not private key",
			input: base64.StdEncoding.EncodeToString([]byte("just some random text here")),
			want:  nil,
		},
		{
			name:  "invalid - too short base64",
			input: `KEY="YWJjZGVm"`, // "abcdef" encoded - too short
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords %v not found in input", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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

func TestBase64PrivateKey_FromData(t *testing.T) {
	rsaPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z6ca1yP6DGV/t5Z3i3h4z3Y8oHs5vZ0N2TQzL1d5dX5w3e
-----END RSA PRIVATE KEY-----`
	validBase64 := base64.StdEncoding.EncodeToString([]byte(rsaPrivateKey))

	tests := []struct {
		name       string
		input      string
		wantResult []detectors.Result
	}{
		{
			name:  "base64 private key detected",
			input: `PRIVATE_KEY="` + validBase64 + `"`,
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_Base64PrivateKey,
					Raw:          []byte(validBase64),
					Verified:     false, // Private keys cannot be verified without context
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{}
			got, err := s.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if diff := cmp.Diff(
				test.wantResult,
				got,
				cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "SecretParts"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
			); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBase64PrivateKey_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_Base64PrivateKey, s.Type())
}

func TestBase64PrivateKey_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "private")
	require.Contains(t, s.Keywords(), "key")
}
