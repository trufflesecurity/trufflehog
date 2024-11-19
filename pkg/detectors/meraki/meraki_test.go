package meraki

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// example picked from: https://github.com/CiscoLearning/ciscolive-ltrcrt-1100/blob/cd0b8f14883ccd70e2db370f8f7a36534bdfe073/02-intro-python/code/meraki_api_info.md?plain=1#L8
	validPattern = `Information used in API calls for meraki
Variable name | Initial Value
apiKey |e9e0f062f587b423bb6cc6328eb786d75b45783e
baseUrl |https://api.meraki.com/api/v1
organizationId |646829496481091262
networkId |L_646829496481117067
serial |`

	validPatternWithNoKeyword = `Information used in API calls
Variable name | Initial Value
apiKey |e9e0f062f587b423bb6cc6328eb786d75b45783e
baseUrl |https://api.meraki.com/api/v1
organizationId |646829496481091262
networkId |L_646829496481117067
serial |`

	invalidPattern = "001A1E0092C7a711d7679d%d0d442d59b05ce65D"
)

func TestMeraki_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("meraki token = '%s'", validPattern),
			want:  []string{"e9e0f062f587b423bb6cc6328eb786d75b45783e"},
		},
		{
			name:  "valid pattern - out of prefix range",
			input: fmt.Sprintf("meraki token keyword is not close to the real token = '%s'", validPatternWithNoKeyword),
			want:  nil,
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("meraki = '%s'", invalidPattern),
			want:  nil,
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

func TestMeraki_Fake(t *testing.T) {
	// mock response data
	mockOrganizations := []merakiOrganizations{
		{ID: "123", Name: "Example Organization 1"},
		{ID: "456", Name: "Example Organization 2"},
	}
	mockResponse, err := json.Marshal(mockOrganizations)
	if err != nil {
		t.Fatalf("failed to marshal mock organizations: %v", err)
	}

	// create a fake HTTP handler function
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the Authorization Header
		if r.Header.Get("X-Cisco-Meraki-API-Key") != "e9e0f062f587b423bb6cc6328eb786d75b45783e" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// this is to test the failed decoding scenario
		if r.Header.Get("X-Cisco-Meraki-API-Key") == "failed-to-decode" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id": 123}`))

			return
		}

		// Send back mock response for 200 OK
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockResponse)
	})
	// create a mock server
	server := CreateMockServer(handler)
	defer server.Close()

	// test cases
	tests := []struct {
		name     string
		secret   string
		verified bool
		wantErr  bool
	}{
		{
			name:     "success - 200 OK",
			secret:   "e9e0f062f587b423bb6cc6328eb786d75b45783e",
			verified: true,
			wantErr:  false,
		},
		{
			name:     "fail - 401 UnAuthorized",
			secret:   "e9e0f062f587b423bb6cc6328eb786d75b45783f",
			verified: false,
			wantErr:  false,
		},
		{
			name:     "fail - failed to decode response",
			secret:   "failed-to-decode",
			verified: false,
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// calling FromData does not work cause APIURLs are hardcoded
			_, isVerified, verificationErr := verifyMerakiApiKey(context.Background(), server.Client(), server.URL, test.secret)
			if verificationErr != nil && !test.wantErr {
				t.Errorf("verification failed; got error, want: %t", test.wantErr)
			}

			if isVerified != test.verified {
				t.Errorf("verification failed; isVerified: %t, want: %t", isVerified, test.verified)
			}

			// additional checks if required
		})
	}
}

// this i am thinking to move to common
// CreateMockServer creates a mock HTTP server with a given handler function.
func CreateMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	// Create and return a new mock server
	return httptest.NewServer(http.HandlerFunc(handler))
}
