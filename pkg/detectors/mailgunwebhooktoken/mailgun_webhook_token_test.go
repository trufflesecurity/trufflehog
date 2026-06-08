package mailgunwebhooktoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestMailgunWebhookToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - webhook signing assignment",
			input: `MAILGUN_WEBHOOK_SIGNING_KEY="9f86d081884c7d659a2feaa0c55ad015"`,
			want:  []string{"9f86d081884c7d659a2feaa0c55ad015"},
		},
		{
			name:  "valid pattern - uppercase hex",
			input: `mailgun webhook token = "0123456789ABCDEF0123456789ABCDEF"`,
			want:  []string{"0123456789ABCDEF0123456789ABCDEF"},
		},
		{
			name: "valid pattern - multiple tokens",
			input: `mailgun primary webhook signing key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mailgun backup webhook signing key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`,
			want: []string{
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name:  "deduplication - repeated token",
			input: `mailgun webhook signing token cccccccccccccccccccccccccccccccc mailgun webhook signing token cccccccccccccccccccccccccccccccc`,
			want:  []string{"cccccccccccccccccccccccccccccccc"},
		},
		{
			name:  "invalid pattern - too short",
			input: `mailgun webhook signing key = "abc123"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - non-hex characters",
			input: `mailgun webhook signing key = "gggggggggggggggggggggggggggggggg"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - missing mailgun context",
			input: `webhook signing key = "dddddddddddddddddddddddddddddddd"`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords %v not found in input", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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

func TestMailgunWebhookToken_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_MailgunWebhookToken, s.Type())
}

func TestMailgunWebhookToken_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "mailgun")
	require.Contains(t, s.Keywords(), "webhook")
	require.Contains(t, s.Keywords(), "signing")
}
