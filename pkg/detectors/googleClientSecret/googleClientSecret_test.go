package googleclientsecret

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestScanner_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name        string
		input       string
		wantMatches []string
	}{
		{
			name:        "bare GOCSPX token",
			input:       `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`,
			wantMatches: []string{"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"},
		},
		{
			name: "token inside JSON client_secret field",
			input: `{
				"client_id":     "123456789012-zq7x.apps.googleusercontent.com",
				"client_secret": "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"
			}`,
			wantMatches: []string{"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"},
		},
		{
			name: "token in env var assignment",
			input: `GOOGLE_CLIENT_SECRET=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
					GOOGLE_CLIENT_ID=123456789012-someid.apps.googleusercontent.com`,
			wantMatches: []string{"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"},
		},
		{
			name: "token in YAML config",
			input: `google:client_secret: "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"
					client_id: "987654321098-xyz.apps.googleusercontent.com"`,
			wantMatches: []string{"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"},
		},
		{
			name: "multiple tokens in same chunk — both detected",
			input: `SECRET_A=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
					SECRET_B=GOCSPX-zzzzyyyyxxxxwwwwvvvvuuuuttt2`,
			wantMatches: []string{
				"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",
				"GOCSPX-zzzzyyyyxxxxwwwwvvvvuuuuttt2",
			},
		},
		{
			name:        "token too short — not matched",
			input:       `GOCSPX-tooshort12345678`,
			wantMatches: nil,
		},
		{
			name:        "token too long — not matched",
			input:       `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Z`,
			wantMatches: nil,
		},
		{
			name:        "token with invalid character — not matched",
			input:       `GOCSPX-Xk9mT2nQ4vL7wP1sT3uY6hJ8b!`,
			wantMatches: nil,
		},
		{
			name:        "unrelated text — no match",
			input:       `This is just some ordinary log output with no secrets.`,
			wantMatches: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(tt.input))
			if len(tt.wantMatches) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("Aho-Corasick: keywords %v not found in input", d.Keywords())
			}

			got, err := d.FromData(context.Background(), false, []byte(tt.input))
			require.NoError(t, err)

			var gotRaw []string
			for _, r := range got {
				gotRaw = append(gotRaw, string(r.Raw))
			}

			if diff := cmp.Diff(
				tt.wantMatches, gotRaw,
				cmpopts.SortSlices(func(a, b string) bool { return a < b }),
				cmpopts.EquateEmpty(),
			); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}

			for _, r := range got {
				if r.Verified {
					t.Errorf("FromData(verify=false): result unexpectedly verified: %s", r.Raw)
				}
			}
		})
	}
}

func TestScanner_FromData_Verify(t *testing.T) {
	const validSecret = "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"
	const inactiveSecret = "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"
	const validClientID = "123456789012-testclientid.apps.googleusercontent.com"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.FormValue("client_secret") {
		case validSecret:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Code was already redeemed."}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_client","error_description":"The OAuth client was not found."}`)
		}
	}))
	defer mockServer.Close()

	tests := []struct {
		name       string
		input      string
		wantResult []detectors.Result
	}{
		{
			name:  "verified — valid secret with paired client_id",
			input: fmt.Sprintf(`{"client_id":%q,"client_secret":%q}`, validClientID, validSecret),
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_GoogleClientSecret,
					Raw:          []byte(validSecret),
					RawV2:        []byte(validClientID + ":" + validSecret),
					Verified:     true,
				},
			},
		},
		{
			name:  "verified — valid secret without client_id",
			input: fmt.Sprintf(`export GOOGLE_SECRET=%q`, validSecret),
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_GoogleClientSecret,
					Raw:          []byte(validSecret),
					Verified:     true,
				},
			},
		},
		{
			name:  "unverified — inactive secret",
			input: fmt.Sprintf(`client_secret=%s`, inactiveSecret),
			wantResult: []detectors.Result{
				{
					DetectorType: detector_typepb.DetectorType_GoogleClientSecret,
					Raw:          []byte(inactiveSecret),
					Verified:     false,
				},
			},
		},
		{
			name:       "no match — no GOCSPX token present",
			input:      `GOOGLE_CLIENT_SECRET=some_old_style_secret_without_prefix`,
			wantResult: []detectors.Result{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: mockServer.Client(), verifyURL: mockServer.URL}
			got, err := s.FromData(context.Background(), true, []byte(tt.input))
			require.NoError(t, err)

			if diff := cmp.Diff(
				tt.wantResult, got,
				cmpopts.IgnoreFields(detectors.Result{}, "ExtraData", "SecretParts"),
				cmpopts.IgnoreUnexported(detectors.Result{}),
				cmpopts.SortSlices(func(a, b detectors.Result) bool { return string(a.Raw) < string(b.Raw) }),
				cmpopts.EquateEmpty(),
			); diff != "" {
				t.Errorf("FromData() mismatch (-want +got):\n%s", diff)
			}

			for _, r := range got {
				if r.Verified && r.VerificationError() != nil {
					t.Errorf("verified result has unexpected VerificationError: %v", r.VerificationError())
				}
				if r.SecretParts["key"] == "" {
					t.Errorf("SecretParts[\"key\"] not set on result %s", r.Raw)
				}
			}
		})
	}
}

func TestScanner_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_GoogleClientSecret, s.Type())
}

func TestScanner_Description(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Description())
}

func TestScanner_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "GOCSPX-")
}

func BenchmarkFromData(b *testing.B) {
	s := Scanner{}
	data := []byte(`
		Some source file content with a secret buried in it.
		GOOGLE_CLIENT_SECRET=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
		Other unrelated config values here.
	`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.FromData(context.Background(), false, data)
	}
}
