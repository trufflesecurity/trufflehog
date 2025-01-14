package v1

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestHubspotV1_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "hapikey",
			input: `// const hapikey = 'b714cac4-a45c-42af-9905-da4de8838d75';
const { HAPI_KEY } = process.env;
const hs = new HubSpotAPI({ hapikey: HAPI_KEY });`,
			want: []string{"b714cac4-a45c-42af-9905-da4de8838d75"},
		},
		// TODO: Doesn't work because it's more than 40 characters.
		//	{
		//		name: "hubapi",
		//		input: `curl https://api.hubapi.com/contacts/v1/lists/all/contacts/all \
		// --header "Authorization: Bearer b71aa2ed-9c76-417d-bd8e-c5f4980d21ef"`,
		//		want: []string{"b71aa2ed-9c76-417d-bd8e-c5f4980d21ef"},
		//	},
		{
			name: "hubspot_1",
			input: `const hs = new HubSpotAPI("76a836c8-469d-4426-8a3b-194ca930b7a1");

const blogPosts = hs.blog.getPosts({ name: 'Inbound' });`,
			want: []string{"76a836c8-469d-4426-8a3b-194ca930b7a1"},
		},
		{
			name: "hubspot_2",
			input: `	'hubspot' => [
	       // 'api_key' => 'e9ff285d-6b7f-455a-a56d-9ec8c4abbd47',         // @ts dev`,
			want: []string{"e9ff285d-6b7f-455a-a56d-9ec8c4abbd47"},
		},
		{
			name: "hubspot_3",
			input: `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "HubSpotAPIKey",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"hubspot_secret": "hDNxPGyQ-AOMZ-w9Sp-aw5t-TwKLBQjQ85go"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`,
			want: []string{"hDNxPGyQ-AOMZ-w9Sp-aw5t-TwKLBQjQ85go"},
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
