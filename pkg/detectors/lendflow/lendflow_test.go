package lendflow

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "RODlvb3v108LswHD7gCZcyHdCIK8T90Hgg12.VF24VyD6akOZS1NmAZ4tVRmtyhyLeNELvCqZnBuiAtJqyMUN2JQHC6vQgzrcAMwPglMjiAZ8gBPIVsQSRiHDvJA89BPQpjAOCxGQynOoSvECoSH5WCldSnl8lN0BNKyeK9J0DSKitEaS9G00qVY9emKcNEQWCWXZeZXLsDXReCcOUEr1Cmi1tpsueqxT34TG4zvaPa2npM10TCKLqKsJrdfZL4oWtZVnZob0QBBkU7k.nQcGbtHUBtYXGUIQYZ1Et1ROaE4Rg0gM-Kw3YtvcVgoV5ro02tydPtPGqSAzf5SBt3LYqQriHmcmW5cx-tASACVQwoT1dpJtxrUP1sa5mHuvstgxDFVe1DxDpMjXYVNL3immaAxqnD6NHs4FzKdNvXvz7p969aIe9q7YdpdyDbFL6x2FINKkqrJ2uMIUNvECITzDjHLGQP3hDcbfJUQ47bDAi3XpbqtFhZTlDd29VwxfEMoA3xi-6rKIS9xXsRxCsLdEt3mhwIxEW89oXKLFHxjXYMGNvl-91H2hw0TIvhzXJHrG3VE1NKXq9E1WoC6OfQPa7qV-lz26nq1jGSW7ENR9HWfc4ppiHj20PGczp6YZPRUIbaTcrOi64F09uOKLInZCIIKI94-bqjlEK5dAune7Fm8pmRqOUPIEnRydJi4ilWiG2cm1xDgU4nb3F507dsjHVi-V0TFyrI-69lrF0TEh7jb8sBjU6yusaRGdannDKBFSnz2d3LVVAn7udGuk2ZNIjYi6equNRYhQ3wJnKQCGIqLaGGQdgH9ILiDB0T9e5aED0taqYpvMFgby6UJGJeNatazX1KMj1NMwMWd3ZIBia7Dlc1lkbWlePlQEh2mZTBcOsvh7lOzLmIu1NKDzByZI3VUhKq5wY3JXJdGeiD3EBPphUt5eaz9Mt0nrK8J"
	invalidPattern = "?ODlvb3v108LswHD7gCZcyHdCIK8T90Hgg12.VF24VyD6akOZS1NmAZ4tVRmtyhyLeNELvCqZnBuiAtJqyMUN2JQHC6vQgzrcAMwPglMjiAZ8gBPIVsQSRiHDvJA89BPQpjAOCxGQynOoSvECoSH5WCldSnl8lN0BNKyeK9J0DSKitEaS9G00qVY9emKcNEQWCWXZeZXLsDXReCcOUEr1Cmi1tpsueqxT34TG4zvaPa2npM10TCKLqKsJrdfZL4oWtZVnZob0QBBkU7k.nQcGbtHUBtYXGUIQYZ1Et1ROaE4Rg0gM-Kw3YtvcVgoV5ro02tydPtPGqSAzf5SBt3LYqQriHmcmW5cx-tASACVQwoT1dpJtxrUP1sa5mHuvstgxDFVe1DxDpMjXYVNL3immaAxqnD6NHs4FzKdNvXvz7p969aIe9q7YdpdyDbFL6x2FINKkqrJ2uMIUNvECITzDjHLGQP3hDcbfJUQ47bDAi3XpbqtFhZTlDd29VwxfEMoA3xi-6rKIS9xXsRxCsLdEt3mhwIxEW89oXKLFHxjXYMGNvl-91H2hw0TIvhzXJHrG3VE1NKXq9E1WoC6OfQPa7qV-lz26nq1jGSW7ENR9HWfc4ppiHj20PGczp6YZPRUIbaTcrOi64F09uOKLInZCIIKI94-bqjlEK5dAune7Fm8pmRqOUPIEnRydJi4ilWiG2cm1xDgU4nb3F507dsjHVi-V0TFyrI-69lrF0TEh7jb8sBjU6yusaRGdannDKBFSnz2d3LVVAn7udGuk2ZNIjYi6equNRYhQ3wJnKQCGIqLaGGQdgH9ILiDB0T9e5aED0taqYpvMFgby6UJGJeNatazX1KMj1NMwMWd3ZIBia7Dlc1lkbWlePlQEh2mZTBcOsvh7lOzLmIu1NKDzByZI3VUhKq5wY3JXJdGeiD3EBPphUt5eaz9Mt0nrK8J"
	keyword        = "lendflow"
)

func TestLendflow_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword lendflow",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
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
