package v2

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

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

func TestHubspotV2_Verify(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "valid token",
			status:       200,
			body:         `[{"name":"private-apps-api-calls-daily","usageLimit":250000,"currentUsage":12}]`,
			wantVerified: true,
		},
		{
			name:    "200 with HTML body from a proxy",
			status:  200,
			body:    "<html><body>Access to this site is blocked</body></html>",
			wantErr: true,
		},
		{
			name:   "invalid token",
			status: 401,
			body:   `{"status":"error","message":"Authentication credentials not found.","category":"INVALID_AUTHENTICATION"}`,
		},
		{
			name:         "valid token missing scopes",
			status:       403,
			body:         `{"status":"error","message":"This app hasn't been granted all required scopes to make this call.","errors":[{"message":"One or more of the following scopes are required.","context":{"requiredGranularScopes":["oauth"]}}],"category":"MISSING_SCOPES"}`,
			wantVerified: true,
		},
		{
			name:    "403 from a proxy",
			status:  403,
			body:    "<html><body>403 Forbidden</body></html>",
			wantErr: true,
		},
		{
			name:    "403 with empty body",
			status:  403,
			wantErr: true,
		},
		{
			name:    "403 with JSON but not a scope error",
			status:  403,
			body:    `{"status":"error","message":"Forbidden"}`,
			wantErr: true,
		},
		{
			name:    "server error",
			status:  500,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(test.status, test.body)
			verified, err := verifyToken(context.Background(), client, "pat-na1-ffbb9f50-d96b-4abc-84f1-b986617be1b5")

			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
		})
	}
}
