package infisical

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// A synthetic token in the exact shape Infisical issues:
	// st.<uuid>.<32 lowercase hex>. Not a real credential.
	validToken   = "st.550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcdef"
	validPattern = `
		# Infisical configuration
		infisical_token: "st.550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcdef"
	`
)

func TestInfisical_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{validToken},
		},
		{
			name:  "invalid pattern - short secret",
			input: `token: "st.550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcde"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - not a uuid",
			input: `token: "st.not-a-uuid.0123456789abcdef0123456789abcdef"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - missing prefix",
			input: `token: "550e8400-e29b-41d4-a716-446655440000.0123456789abcdef0123456789abcdef"`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
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
				actual[string(r.Raw)] = struct{}{}
				if r.SecretParts["key"] == "" {
					t.Errorf("SecretParts not populated")
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

func TestInfisical_Verification(t *testing.T) {
	d := Scanner{}

	// A synthetic token that matches the pattern but does not exist in
	// Infisical. Verification must not mark it verified.
	results, err := d.FromData(context.Background(), true, []byte(validToken))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verified {
		t.Errorf("synthetic token should not verify")
	}
	if results[0].DetectorType.String() != "Infisical" {
		t.Errorf("expected DetectorType Infisical, got %s", results[0].DetectorType.String())
	}
}
