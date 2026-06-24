package visiblenpmregistryauthdata

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

func TestVisibleNpmRegistryAuthData_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	validNpmToken := "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	validAuthValue := "dXNlcm5hbWU6cGFzc3dvcmQ="

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid _authToken in npmrc",
			input: `//registry.npmjs.org/:_authToken=` + validNpmToken,
			want:  []string{validNpmToken},
		},
		{
			name:  "valid scoped _authToken",
			input: `@my-org:registry=https://registry.npmjs.org/` + "\n" + `//registry.npmjs.org/:_authToken=` + validNpmToken,
			want:  []string{validNpmToken},
		},
		{
			name:  "valid _auth in npmrc",
			input: `//registry.npmjs.org/:_auth=` + validAuthValue,
			want:  []string{validAuthValue},
		},
		{
			name: "valid both _authToken and _auth",
			input: `//registry.npmjs.org/:_authToken=` + validNpmToken + `
//registry.npmjs.org/:_auth=` + validAuthValue,
			want: []string{validNpmToken, validAuthValue},
		},
		{
			name:  "deduplication repeated _authToken",
			input: `//registry.npmjs.org/:_authToken=` + validNpmToken + "\n" + `//registry.npmjs.org/:_authToken=` + validNpmToken,
			want:  []string{validNpmToken},
		},
		{
			name:  "invalid pattern key name mismatch",
			input: `//registry.npmjs.org/:authToken=` + validNpmToken,
			want:  nil,
		},
		{
			name:  "invalid _auth too short",
			input: `//registry.npmjs.org/:_auth=abcd123`,
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

func TestVisibleNpmRegistryAuthData_Verify(t *testing.T) {
	validToken := "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	invalidToken := "npm_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if authHeader == "Bearer "+validToken {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"username":"tester"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"auth required"}`))
	}))
	defer mockServer.Close()

	tests := []struct {
		name       string
		input      string
		wantResult []detectors.Result
	}{
		{
			name:  "verified _authToken value",
			input: `//registry.npmjs.org/:_authToken=` + validToken,
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VisibleNpmRegistryAuthData,
					Raw:          []byte(validToken),
					Verified:     true,
				},
			},
		},
		{
			name:  "unverified _authToken value",
			input: `//registry.npmjs.org/:_authToken=` + invalidToken,
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VisibleNpmRegistryAuthData,
					Raw:          []byte(invalidToken),
					Verified:     false,
				},
			},
		},
		{
			name:  "auth value present but not verifyable token",
			input: `//registry.npmjs.org/:_auth=dXNlcm5hbWU6cGFzc3dvcmQ=`,
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_VisibleNpmRegistryAuthData,
					Raw:          []byte("dXNlcm5hbWU6cGFzc3dvcmQ="),
					Verified:     false,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: mockServer.Client(), registryBaseURL: mockServer.URL}
			got, err := s.FromData(context.Background(), true, []byte(test.input))
			require.NoError(t, err)

			if diff := cmp.Diff(
				test.wantResult,
				got,
				cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "SecretParts"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
				cmpopts.SortSlices(func(a, b detectors.Result) bool { return string(a.Raw) < string(b.Raw) }),
				cmpopts.EquateEmpty(),
			); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVisibleNpmRegistryAuthData_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_VisibleNpmRegistryAuthData, s.Type())
}

func TestVisibleNpmRegistryAuthData_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "_authToken")
	require.Contains(t, s.Keywords(), "_auth")
}


// func TestVisibleNpmRegistryAuthData_RealTokenCheck(t *testing.T) {
// 	token := "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
// 	if strings.TrimSpace(token) == "" {
// 		t.Skip("set token in TestVisibleNpmRegistryAuthData_RealTokenCheck for manual real-token verification")
// 	}

// 	input := []byte("//registry.npmjs.org/:_authToken=" + token)
// 	s := Scanner{}

// 	results, err := s.FromData(context.Background(), true, input)
// 	require.NoError(t, err)
// 	require.NotEmpty(t, results, "expected detector to find provided token")

// 	r := results[0]
// 	t.Logf("raw=%s verified=%t verification_error=%v", string(r.Raw), r.Verified, r.VerificationError())
// 	require.True(t, r.Verified, "expected active npm auth token to verify successfully")
// }
