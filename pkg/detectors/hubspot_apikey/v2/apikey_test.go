package v2

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// stubTransport returns a canned response without touching the network.
type stubTransport struct {
	statusCode int
	body       string
}

func (t *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: t.statusCode,
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Header:     make(http.Header),
	}, nil
}

func TestVerifyToken(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{
			name:       "ok",
			statusCode: http.StatusOK,
			body:       `{"status":"ok"}`,
			want:       true,
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			body:       `{"status":"error","message":"Authentication credentials not found."}`,
			want:       false,
		},
		{
			name:       "forbidden api json error means valid token",
			statusCode: http.StatusForbidden,
			body:       `{"status":"error","message":"The token is valid but lacks permission.","correlationId":"abc123"}`,
			want:       true,
		},
		{
			name:       "forbidden waf block page is not verified",
			statusCode: http.StatusForbidden,
			body:       "<html><body>You have been blocked.</body></html>",
			want:       false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: &stubTransport{statusCode: test.statusCode, body: test.body}}
			got, err := verifyToken(context.Background(), client, "pat-na1-deadbeef-0000-1111-2222-333344445555")
			if err != nil {
				t.Fatalf("verifyToken() error = %v", err)
			}
			if got != test.want {
				t.Errorf("verifyToken() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestHubspotV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "eu key",
			input: `
const private_app_token = 'pat-eu1-1457aed5-04c6-40e2-83ad-a862d3cf19f2';

app.get('/homepage', async (req, res) => {
    const contactsEndpoint = 'https://api.hubspot.com/crm/v3/objects/contacts';`,
			want: []string{"pat-eu1-1457aed5-04c6-40e2-83ad-a862d3cf19f2"},
		},
		{
			name: "na key",
			input: `hubspot:
   api:
      url: https://api.hubapi.com
      auth-token: pat-na1-ffbb9f50-d96b-4abc-84f1-b986617be1b5
   subscriptions:`,
			want: []string{"pat-na1-ffbb9f50-d96b-4abc-84f1-b986617be1b5"},
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
