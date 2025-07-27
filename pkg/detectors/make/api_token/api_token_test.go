package api_token

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestMake_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name      string
		input     string
		wantRaw   []string
		wantRawV2 []string
	}{
		{
			name:    "typical pattern - token only",
			input:   "make_token = 'bbb94d50-239f-4609-9569-63ea15eb0996'",
			wantRaw: []string{"bbb94d50-239f-4609-9569-63ea15eb0996"},
		},
		{
			name:      "pattern with URL context",
			input:     "url = 'https://eu1.make.com/api/v2/' make_token = 'bbb94d50-239f-4609-9569-63ea15eb0996'",
			wantRaw:   []string{"bbb94d50-239f-4609-9569-63ea15eb0996"},
			wantRawV2: []string{"bbb94d50-239f-4609-9569-63ea15eb0996:https://eu1.make.com/api/v2/"},
		},
		{
			name: "finds all token matches",
			input: `make_token1 = 'bbb94d50-239f-4609-9569-63ea15eb0996'
make_token2 = 'f61ec443-95f2-4a8c-bda7-3f76f7a6beba'`,
			wantRaw: []string{"bbb94d50-239f-4609-9569-63ea15eb0996", "f61ec443-95f2-4a8c-bda7-3f76f7a6beba"},
		},
		{
			name: "finds all token matches with URL context",
			input: `url1 = 'https://eu1.make.com/api/v2/' make_token1 = 'bbb94d50-239f-4609-9569-63ea15eb0996' 
url2 = 'https://eu2.make.com/api/v2/' make_token2 = 'bbb94d50-239f-4609-9569-63ea15eb0997'`,
			wantRaw:   []string{"bbb94d50-239f-4609-9569-63ea15eb0996", "bbb94d50-239f-4609-9569-63ea15eb0997"},
			wantRawV2: []string{"bbb94d50-239f-4609-9569-63ea15eb0996:https://eu1.make.com/api/v2/", "bbb94d50-239f-4609-9569-63ea15eb0997:https://eu2.make.com/api/v2/", "bbb94d50-239f-4609-9569-63ea15eb0996:https://eu2.make.com/api/v2/", "bbb94d50-239f-4609-9569-63ea15eb0997:https://eu1.make.com/api/v2/"},
		},
		{
			name:      "celonis domain",
			input:     "url = 'https://us1.make.celonis.com/api/v2/' token = 'aaa94d50-239f-4609-9569-63ea15eb0996'",
			wantRaw:   []string{"aaa94d50-239f-4609-9569-63ea15eb0996"},
			wantRawV2: []string{"aaa94d50-239f-4609-9569-63ea15eb0996:https://us1.make.celonis.com/api/v2/"},
		},
		{
			name:    "invalid pattern - not UUID format",
			input:   "make_token = '1a2b3c4d'",
			wantRaw: []string{},
		},
		{
			name:    "invalid pattern - wrong UUID format",
			input:   "make_token = 'bbb94d50-239f-4609-9569-63ea15eb09961'", // too long
			wantRaw: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.wantRaw) > 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			expectedResultCount := len(test.wantRaw)
			if len(test.wantRawV2) > 0 {
				expectedResultCount = len(test.wantRawV2)
			}
			if len(results) != expectedResultCount {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", expectedResultCount, len(results))
				}
				return
			}

			// Check Raw values
			actualRaw := make(map[string]struct{}, len(results))
			for _, r := range results {
				actualRaw[string(r.Raw)] = struct{}{}
			}
			expectedRaw := make(map[string]struct{}, len(test.wantRaw))
			for _, v := range test.wantRaw {
				expectedRaw[v] = struct{}{}
			}

			if diff := cmp.Diff(expectedRaw, actualRaw); diff != "" {
				t.Errorf("%s Raw diff: (-want +got)\n%s", test.name, diff)
			}

			// Check RawV2 values if expected
			if len(test.wantRawV2) > 0 {
				actualRawV2 := make(map[string]struct{}, len(results))
				for _, r := range results {
					if len(r.RawV2) > 0 {
						actualRawV2[string(r.RawV2)] = struct{}{}
					}
				}
				expectedRawV2 := make(map[string]struct{}, len(test.wantRawV2))
				for _, v := range test.wantRawV2 {
					expectedRawV2[v] = struct{}{}
				}

				if diff := cmp.Diff(expectedRawV2, actualRawV2); diff != "" {
					t.Errorf("%s RawV2 diff: (-want +got)\n%s", test.name, diff)
				}
			}
		})
	}
}
