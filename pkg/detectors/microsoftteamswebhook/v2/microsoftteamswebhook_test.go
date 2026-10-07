package microsoftteamswebhook

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern          = "https://defaultabc123def456abc123def456ab.62.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/67b9621a4a744d4abc90035cb396b361/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=r2h9kxq06-gWOJ7QiEHNTxntTw11k2uJA3EZr0SIcIQ"
	validPatternReordered = "https://defaultabc123def456abc123def456ab.62.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/67b9621a4a744d4abc90035cb396b361/triggers/manual/paths/invoke?sig=r2h9kxq06-gWOJ7QiEHNTxntTw11k2uJA3EZr0SIcIQ&api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0"
	invalidPattern        = "https://defaultabc123.webhook.office.com/webhookb2/not-a-v2-url"
	noSigPattern          = "https://defaultabc123def456abc123def456ab.62.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/67b9621a4a744d4abc90035cb396b361/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0"
)

func TestScanner_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("teams webhook url = '%s'", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - sig first",
			input: fmt.Sprintf("teams webhook url = '%s'", validPatternReordered),
			want:  []string{validPatternReordered},
		},
		{
			name:  "invalid pattern - wrong domain",
			input: fmt.Sprintf("webhook = '%s'", invalidPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern - missing sig",
			input: fmt.Sprintf("webhook = '%s'", noSigPattern),
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := ahoCorasickCore.FindDetectorMatches([]byte(tt.input))
			if len(tt.want) > 0 && len(matched) == 0 {
				t.Errorf("keywords not matched")
				return
			}
			results, err := d.FromData(context.Background(), false, []byte(tt.input))
			if err != nil {
				t.Fatal(err)
			}
			actual := make(map[string]struct{})
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{})
			for _, v := range tt.want {
				expected[v] = struct{}{}
			}
			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("(-want +got)\n%s", diff)
			}
		})
	}
}
