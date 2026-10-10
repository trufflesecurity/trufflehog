package paystack

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "sk_xigrvarm_cJHGpWQwCTHajG2A2o8eC8TQaQGZdoMVhgXUA9Lm"
	invalidPattern = "sk_xigrvarm_cJHGpWQwCTHajG?A2o8eC8TQaQGZdoMVhgXUA9Lm"
	keyword        = "paystack"
)

func TestPaystack_Pattern(t *testing.T) {
	d := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "valid pattern", input: fmt.Sprintf("%s token = '%s'", keyword, validPattern), want: []string{validPattern}},
		{name: "invalid pattern", input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern), want: []string{}},
		{name: "test key keyword", input: "sk_test_abcdefghijklmnopqrstuvwxyz1234567890abcd", want: []string{"sk_test_abcdefghijklmnopqrstuvwxyz1234567890abcd"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(core.FindDetectorMatches([]byte(tc.input))) == 0 {
				t.Fatalf("keywords %v did not match input", d.Keywords())
			}
			results, err := d.FromData(context.Background(), false, []byte(tc.input))
			if err != nil {
				t.Fatalf("FromData error: %v", err)
			}
			got := make(map[string]struct{}, len(results))
			for _, result := range results {
				got[string(result.Raw)] = struct{}{}
				if result.SecretParts["key"] != string(result.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", result.SecretParts["key"], result.Raw)
				}
			}
			want := make(map[string]struct{}, len(tc.want))
			for _, value := range tc.want {
				want[value] = struct{}{}
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}
