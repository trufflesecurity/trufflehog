package composio

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Synthetic vectors from Composio's published format spec; none were ever minted.
const (
	projectKey        = "ak_jI60uPF6adMkCuBFESjq"
	projectKeyDashEnd = "ak_Qbez9ytnft9XyXAGPL0-"
	orgKey            = "oak_iuGvTZ4eiiy3umBWjwTt"
	userKey           = "uak_TRFvy_o-mFznI3IyljByM5LL-SudKFv47vULpKuK2ai"
)

func TestComposio_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "project key", input: fmt.Sprintf("COMPOSIO_API_KEY=%s", projectKey), want: []string{projectKey}},
		{name: "project key ending in dash", input: fmt.Sprintf("key: '%s'", projectKeyDashEnd), want: []string{projectKeyDashEnd}},
		{name: "org key is reported once, not also as a project key", input: fmt.Sprintf("COMPOSIO_ORG_KEY=%s", orgKey), want: []string{orgKey}},
		{name: "user key is reported once, not also as a project key", input: fmt.Sprintf("x-user-api-key: %s", userKey), want: []string{userKey}},
		{name: "duplicates collapse", input: fmt.Sprintf("%s %s", projectKey, projectKey), want: []string{projectKey}},
		{name: "two keys separated by a single comma are both reported", input: fmt.Sprintf("%s,%s", projectKey, projectKeyDashEnd), want: []string{projectKey, projectKeyDashEnd}},
		{name: "key glued to a following alphabet character is not a key", input: fmt.Sprintf("%sZ", projectKey), want: []string{}},
		{name: "wrong length", input: "COMPOSIO_API_KEY=ak_jI60uPF6adMkCuBFESj", want: []string{}},
		{name: "placeholder", input: "COMPOSIO_API_KEY=ak_test", want: []string{}},
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

func TestComposio_KeyType(t *testing.T) {
	d := Scanner{}
	results, err := d.FromData(context.Background(), false, []byte(orgKey))
	if err != nil || len(results) != 1 {
		t.Fatalf("expected one result, got %d (err %v)", len(results), err)
	}
	if got := results[0].ExtraData["key_type"]; got != "org" {
		t.Errorf("key_type = %q, want org", got)
	}
}
