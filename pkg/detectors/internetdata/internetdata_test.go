package internetdata

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Synthetic keys in the published format; none were ever minted.
const (
	validKey        = "mk_3f9a1c2e_Zq8LwP0vT4nR7yB2xK9mC5dH1jG6sF3a"
	validKeyDashEnd = "mk_0b7d44a1_Hk2_pV9wQ4tL8nX1cB7mR3zD6fJ0sA5-"
)

func TestInternetData_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "env file", input: fmt.Sprintf("INTERNETDATA_API_KEY=%s", validKey), want: []string{validKey}},
		{name: "header", input: fmt.Sprintf("curl -H 'X-Api-Key: %s' https://api.internetdata.io/8.8.8.8", validKey), want: []string{validKey}},
		{name: "query string", input: fmt.Sprintf("https://api.internetdata.io/1.1.1.1?apikey=%s&fields=asn", validKey), want: []string{validKey}},
		{
			name:  "key with an underscore inside and a dash at the end",
			input: fmt.Sprintf(`{"apiKey": "%s"}`, validKeyDashEnd),
			want:  []string{validKeyDashEnd},
		},
		{name: "duplicates collapse", input: fmt.Sprintf("%s %s", validKey, validKey), want: []string{validKey}},
		{
			name:  "two keys separated by a single comma are both reported",
			input: fmt.Sprintf("%s,%s", validKey, validKeyDashEnd),
			want:  []string{validKey, validKeyDashEnd},
		},
		{name: "key glued to a following alphabet character is not a key", input: validKey + "Z", want: []string{}},
		{name: "key glued to a preceding alphabet character is not a key", input: "x" + validKey, want: []string{}},
		{name: "secret part too short", input: "INTERNETDATA_API_KEY=mk_3f9a1c2e_Zq8LwP0vT4nR7yB2xK9mC5dH1jG6sF3", want: []string{}},
		{name: "prefix not hex", input: "INTERNETDATA_API_KEY=mk_3f9a1c2z_Zq8LwP0vT4nR7yB2xK9mC5dH1jG6sF3a", want: []string{}},
		{name: "placeholder", input: "INTERNETDATA_API_KEY=mk_xxxxxxxx_your-key-here", want: []string{}},
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
				t.Errorf("expected %d results, received %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				actual[string(r.Raw)] = struct{}{}
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

func TestInternetData_SecretParts(t *testing.T) {
	d := Scanner{}
	results, err := d.FromData(context.Background(), false, []byte(validKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected one result, got %d (err %v)", len(results), err)
	}
	if got := results[0].SecretParts["key"]; got != validKey {
		t.Errorf("SecretParts key = %q, want the key", got)
	}
	if got := results[0].ExtraData["rotation_guide"]; got != rotationGuide {
		t.Errorf("rotation_guide = %q, want %q", got, rotationGuide)
	}
}
