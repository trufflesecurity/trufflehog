package flutterwave

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestFlutterWave_Pattern(t *testing.T) {
	d := Scanner{}
	core := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "live secret key",
			input: `{"flutterwave_secret":"FLWSECK-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}`,
			want:  []string{"FLWSECK-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"},
		},
		{
			name:  "test secret key",
			input: `{"flutterwave_secret":"FLWSECK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}`,
			want:  []string{"FLWSECK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"},
		},
		{
			name:  "public key is not a secret key",
			input: `{"flutterwave_public_key":"FLWPUBK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-X"}`,
			want:  []string{},
		},
		{
			name:  "reject malformed key",
			input: `{"flutterwave_secret":"FLWSECK_TEST-aylhdv2oo3wf5tylj8s4d9bqb8adoebx-XX"}`,
			want:  []string{},
		},
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
