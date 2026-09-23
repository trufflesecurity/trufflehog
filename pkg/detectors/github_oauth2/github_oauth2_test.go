package github_oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGithubOAuth2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern - with keyword github",
			input: "github = '9c14koUc3f04PrzlpCcU', 'caa3224b5ddb83924e6a487ee3f6543bae428309'",
			want: []string{
				"9c14koUc3f04PrzlpCcUcaa3224b5ddb83924e6a487ee3f6543bae428309",
			},
		},
		{
			name:  "typical pattern - invalid client ID",
			input: "github = '10c14koUc3f04PrzlpCcU', 'caa3224b5ddb83924e6a487ee3f6543bae428309'",
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

// TestGithubOAuth2_VerifyResult covers the single-pair verification entry point that the
// verification cache calls for cache misses. Verification is pointed at a local server by
// reassigning tokenURL and by handing x/oauth2 a client through the context, since
// clientcredentials resolves its HTTP client from oauth2.HTTPClient.
func TestGithubOAuth2_VerifyResult(t *testing.T) {
	const (
		clientID     = "9c14koUc3f04PrzlpCcU"
		clientSecret = "caa3224b5ddb83924e6a487ee3f6543bae428309"
	)

	tests := []struct {
		name         string
		status       int
		contentType  string
		body         string
		wantVerified bool
	}{
		{
			// GitHub answers a valid ID/secret pair with bad_verification_code, because the
			// client_credentials grant supplies no verification code. It reports this with
			// HTTP 200 rather than a 4xx, which x/oauth2 still surfaces as a RetrieveError
			// because the body carries an error field.
			name:         "live credential - bad_verification_code",
			status:       http.StatusOK,
			contentType:  "application/x-www-form-urlencoded",
			body:         "error=bad_verification_code&error_description=The+code+passed+is+incorrect+or+expired.",
			wantVerified: true,
		},
		{
			name:         "dead credential - incorrect_client_credentials",
			status:       http.StatusUnauthorized,
			contentType:  "application/x-www-form-urlencoded",
			body:         "error=incorrect_client_credentials",
			wantVerified: false,
		},
		{
			// A transient server failure currently lands here as "not verified" rather than
			// "unknown", because verification never calls SetVerificationError. That is a
			// known false negative tracked on its own ticket; this case pins today's behavior
			// so that changing it later is deliberate rather than accidental.
			name:         "server error - recorded unverified rather than unknown",
			status:       http.StatusInternalServerError,
			contentType:  "text/plain",
			body:         "boom",
			wantVerified: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var gotID, gotSecret string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// clientcredentials presents the pair either as basic auth or as form values,
				// depending on which auth style x/oauth2 is probing, so accept both.
				if id, secret, ok := r.BasicAuth(); ok {
					gotID, gotSecret = id, secret
				} else if err := r.ParseForm(); err == nil {
					gotID, gotSecret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
				}
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			originalTokenURL := tokenURL
			tokenURL = server.URL
			t.Cleanup(func() { tokenURL = originalTokenURL })

			// x/oauth2 resolves its HTTP client from the context, which is how verification is
			// redirected at the test server without the detector knowing about it.
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())

			result := detectors.Result{
				Raw:         []byte(clientID),
				RawV2:       []byte(clientID + clientSecret),
				SecretParts: map[string]string{"id": clientID, "secret": clientSecret},
			}
			Scanner{}.VerifyResult(ctx, &result)

			assert.Equal(t, test.wantVerified, result.Verified)
			// Confirms the pair travelled from SecretParts into the token request, which is
			// the contract the verification cache relies on when it verifies a lone result.
			assert.Equal(t, clientID, gotID)
			assert.Equal(t, clientSecret, gotSecret)
		})
	}
}
