package googlegemini

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "AIzaSyDW1PXXav-TxriHUIrj1djZfHKIuInr7Aw"
	invalidPattern = "AIzaSyDW1PXXav-TxriHUIrj1djZfHKIuInr7A"
	// Synthetic new-format Google AI Studio auth key (AQ.-prefixed). The body
	// is intentionally fake filler; real keys look like AQ.Ab8RN6JywhTw4HqaKz…
	validAQPattern = "AQ.Ab8RN6JywhTw4HqaKzTESTDUMMYKEYTEST12"
)

func TestGoogleGemini_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("gemini api key = '%s'", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("gemini api key = '%s'", invalidPattern),
			want:  []string{},
		},
		{
			name:  "valid AQ. auth key pattern",
			input: fmt.Sprintf("gemini api key = '%s'", validAQPattern),
			want:  []string{validAQPattern},
		},
		{
			name:  "valid AQ. auth key in query string",
			input: fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models?key=%s", validAQPattern),
			want:  []string{validAQPattern},
		},
		{
			name:  "AQ. key too short is rejected",
			input: "gemini api key = 'AQ.Ab8'",
			want:  []string{},
		},
		{
			name:  "AQ. key with invalid charset is rejected",
			input: "gemini api key = 'AQ.Ab8RN6JywhTw4HqaKz+TEST'",
			want:  []string{},
		},
		{
			name:  "FAQ. prose is not a key",
			input: "See the FAQ.about-us page for details and more text here",
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
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

// roundTripFunc lets tests stub the transport without touching the network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func cannedResponse(status int) *http.Response {
	return &http.Response{
		Status:     http.StatusText(status),
		StatusCode: status,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}
}

// TestGoogleGemini_VerifyAQKey exercises the verification path for the new
// AQ.-prefixed auth keys against a stubbed transport. Verification reuses the
// same lightweight native endpoint (GET /v1/models with X-goog-api-key) for
// both key formats; AQ. keys are accepted on native Gemini routes.
func TestGoogleGemini_VerifyAQKey(t *testing.T) {
	const (
		liveKey     = "AQ.Ab8RN6JywhTw4HqaKzLIVEKEYTESTDUMMY12"
		noAccessKey = "AQ.Ab8RN6JywhTw4HqaKzNOACCESSDUMMYKEY1"
		deadKey     = "AQ.Ab8RN6JywhTw4HqaKzDEADKEYTESTDUMMY1"
	)

	var requests int
	stub := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Host != "generativelanguage.googleapis.com" {
			t.Errorf("unexpected verification host: %s", r.URL.Host)
		}
		if got := r.URL.Path; got != "/v1/models" {
			t.Errorf("unexpected verification path: %s", got)
		}
		switch key := r.Header.Get("X-goog-api-key"); key {
		case liveKey:
			return cannedResponse(http.StatusOK), nil
		case noAccessKey:
			return cannedResponse(http.StatusForbidden), nil
		default:
			if key != deadKey {
				t.Errorf("unexpected key sent for verification: %s", key)
			}
			return cannedResponse(http.StatusBadRequest), nil
		}
	})

	tests := []struct {
		name         string
		key          string
		wantVerified bool
		wantActive   string
	}{
		{name: "live AQ. key verifies", key: liveKey, wantVerified: true, wantActive: "true"},
		{name: "valid AQ. key without gemini access is not verified but flagged active", key: noAccessKey, wantVerified: false, wantActive: "true"},
		{name: "invalid AQ. key is not verified", key: deadKey, wantVerified: false, wantActive: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests = 0
			d := Scanner{client: &http.Client{Transport: stub}}
			results, err := d.FromData(context.Background(), true, []byte(fmt.Sprintf("gemini = '%s'", test.key)))
			if err != nil {
				t.Fatalf("FromData error = %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if requests != 1 {
				t.Errorf("expected exactly 1 verification request, got %d", requests)
			}
			if results[0].Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", results[0].Verified, test.wantVerified)
			}
			if got := results[0].ExtraData["active_google_key"]; got != test.wantActive {
				t.Errorf("ExtraData[active_google_key] = %q, want %q", got, test.wantActive)
			}
		})
	}
}

// TestGoogleGemini_NoVerifySkipsNetwork ensures verification is only attempted
// when requested, so plain scanning never issues HTTP calls.
func TestGoogleGemini_NoVerifySkipsNetwork(t *testing.T) {
	stub := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Error("verification request issued even though verify=false")
		return cannedResponse(http.StatusOK), nil
	})
	d := Scanner{client: &http.Client{Transport: stub}}
	results, err := d.FromData(context.Background(), false, []byte(fmt.Sprintf("gemini = '%s'", validAQPattern)))
	if err != nil {
		t.Fatalf("FromData error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Error("result marked verified without verification")
	}
}
