package pubnubsubscriptionkey

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "sub-c-sy4te40h-w1oc-zpyq-zlrw-w6ehv0y0y78c"
	invalidPattern = "sub-c-sy4te40h-w1oc-z?yq-zlrw-w6ehv0y0y78c"
	keyword        = "pubnubsubscriptionkey"
)

// TestPubNubSubscriptionKey_VerifyKey tests the 403 body-parsing logic that
// determines whether a key is valid even when the Objects/App Context feature
// is disabled on the PubNub account.
func TestPubNubSubscriptionKey_VerifyKey(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		wantVerified   bool
		wantErrPresent bool
	}{
		{
			name:         "200 OK - key is valid",
			statusCode:   http.StatusOK,
			responseBody: `{"status":200,"data":[]}`,
			wantVerified: true,
		},
		{
			name:         "403 with 'Objects not enabled' - key is valid, feature disabled",
			statusCode:   http.StatusForbidden,
			responseBody: `{"status":403,"error":true,"message":"Objects not enabled for this subscriber key."}`,
			wantVerified: true,
		},
		{
			name:         "403 with 'App Context is not enabled' - key is valid, feature disabled",
			statusCode:   http.StatusForbidden,
			responseBody: `{"status":403,"error":true,"message":"App Context is not enabled for this subscribe key."}`,
			wantVerified: true,
		},
		{
			name:         "403 with other body - key is invalid",
			statusCode:   http.StatusForbidden,
			responseBody: `{"status":403,"error":true,"message":"Invalid subscribe key"}`,
			wantVerified: false,
		},
		{
			name:         "401 Unauthorized - key is invalid",
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"status":401,"error":true}`,
			wantVerified: false,
		},
		{
			name:           "unexpected status code - returns error",
			statusCode:     http.StatusInternalServerError,
			responseBody:   `internal error`,
			wantVerified:   false,
			wantErrPresent: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(test.responseBody))
			}))
			defer srv.Close()

			verified, err := verifyKey(context.Background(), srv.Client(), srv.URL, "test-key")
			if (err != nil) != test.wantErrPresent {
				t.Errorf("wantErr=%v, got err=%v", test.wantErrPresent, err)
			}
			if verified != test.wantVerified {
				t.Errorf("wantVerified=%v, got=%v", test.wantVerified, verified)
			}
		})
	}
}

func TestPubNubSubscriptionKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword pubnubsubscriptionkey",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
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
