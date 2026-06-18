package shippolivetoken

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestShippoLiveToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	validTokenA := "shippo_live_0123456789abcdef0123456789abcdef01234567"
	validTokenB := "shippo_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - auth header style",
			input: `Authorization: ShippoToken ` + validTokenA,
			want:  []string{validTokenA},
		},
		{
			name:  "valid pattern - env var",
			input: `SHIPPO_LIVE_TOKEN="` + validTokenA + `"`,
			want:  []string{validTokenA},
		},
		{
			name: "valid pattern - multiple keys",
			input: `shippo live key1=` + validTokenA + `
shippo live key2=` + validTokenB,
			want: []string{validTokenA, validTokenB},
		},
		{
			name:  "deduplication - repeated key",
			input: `ShippoToken ` + validTokenA + ` ShippoToken ` + validTokenA,
			want:  []string{validTokenA},
		},
		{
			name:  "invalid pattern - wrong prefix",
			input: `Authorization: ShippoToken shippo_test_0123456789abcdef0123456789abcdef01234567`,
			want:  nil,
		},
		{
			name:  "invalid pattern - uppercase hex suffix",
			input: `shippo_live_0123456789ABCDEF0123456789ABCDEF01234567`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too short",
			input: `shippo_live_0123456789abcdef0123456789abcdef`,
			want:  nil,
		},
		{
			name:  "invalid pattern - invalid character",
			input: `shippo_live_0123456789abcdef0123456789abcdef0123456z`,
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

func TestShippoLiveToken_Verify(t *testing.T) {
	validToken := "shippo_live_0123456789abcdef0123456789abcdef01234567"
	invalidToken := "shippo_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		expected := "ShippoToken " + validToken
		switch auth {
		case expected:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"results":[]}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"invalid token"}`))
		}
	}))
	defer mockServer.Close()

	tests := []struct {
		name       string
		input      string
		wantResult []detectors.Result
	}{
		{
			name:  "verified token",
			input: `Authorization: ShippoToken ` + validToken,
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_ShippoLiveToken,
					Raw:          []byte(validToken),
					Verified:     true,
				},
			},
		},
		{
			name:  "unverified token",
			input: `Authorization: ShippoToken ` + invalidToken,
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_ShippoLiveToken,
					Raw:          []byte(invalidToken),
					Verified:     false,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{
				client:     mockServer.Client(),
				apiBaseURL: mockServer.URL,
			}
			got, err := s.FromData(context.Background(), true, []byte(test.input))
			require.NoError(t, err)
			for _, r := range got {
				t.Logf("raw=%s verified=%t verification_error=%v", string(r.Raw), r.Verified, r.VerificationError())
			}

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

func TestShippoLiveToken_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_ShippoLiveToken, s.Type())
}

func TestShippoLiveToken_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "shippo_live_")
	require.Contains(t, s.Keywords(), "ShippoToken")
}
