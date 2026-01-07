package twilio

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validSid   = "AC1b3f0bddbb6887d68d8454e66c749c6a"
	invalidSid = "AC1b3f0bddbb?887d68d8454e66c749c6a"
	validKey   = "daf7b3d34b9787f1212316eea62ba186"
	invalidKey = "daf7b3d34b9787f1?12316eea62ba186"
	keyword    = "twilio"
)

func TestTwilio_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword twilio",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validSid, keyword, validKey),
			want:  []string{validSid + validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidSid, keyword, invalidKey),
			want:  []string{},
		},
		{
			name:  "valid pattern - with keyword twilio",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validSid, keyword, validKey),
			want:  []string{validSid + validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidSid, keyword, invalidKey),
			want:  []string{},
		},

		// "sid" alone should NOT trigger detector
		{
			name:  "sid keyword alone should not trigger detector",
			input: fmt.Sprintf("sid = '%s'\ntoken = '%s'\n", validSid, validKey),
			want:  []string{}, // detector won't even run without "twilio" keyword
		},

		// True positives that MUST still work
		{
			name:  "valid pattern - environment variable style",
			input: fmt.Sprintf("TWILIO_ACCOUNT_SID=%s\nTWILIO_AUTH_TOKEN=%s\n", validSid, validKey),
			want:  []string{validSid + validKey},
		},
		{
			name:  "valid pattern - JSON format",
			input: fmt.Sprintf(`{"twilio": {"accountSid": "%s", "authToken": "%s"}}`, validSid, validKey),
			want:  []string{validSid + validKey},
		},
		{
			name:  "valid pattern - customer reported format (name/value pairs)",
			input: fmt.Sprintf(`twilio config: {"name": "accountSid", "value": "%s"}, {"name": "authToken", "value": "%s"}`, validSid, validKey),
			want:  []string{validSid + validKey},
		},
		{
			name:  "valid pattern - Postman variable style",
			input: fmt.Sprintf(`{"name": "Twilio API", "values": [{"key": "account_sid", "value": "%s"}, {"key": "auth_token", "value": "%s"}]}`, validSid, validKey),
			want:  []string{validSid + validKey},
		},

		// False positive prevention - these should NOT create results
		{
			name: "false positive - generic hex strings with non-twilio context",
			input: `twilio_enabled: true
			aws_secret: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
			stripe_key: b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5
			random_token: c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6`,
			want: []string{}, // No AC-prefixed SID, so no matches
		},
		{
			name: "false positive - MD5 hashes should not match as keys without twilio auth context",
			input: fmt.Sprintf(`twilio_enabled: true
			account_sid: %s
			file_checksum: e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
			content_hash: f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3`, validSid),
			want: []string{}, // hex strings lack twilio/auth/token context
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			// For tests expecting no results due to keyword mismatch, verify detector doesn't trigger
			if len(test.want) == 0 && !strings.Contains(strings.ToLower(test.input), "twilio") {
				if len(matchedDetectors) > 0 {
					t.Errorf("detector should not have triggered without 'twilio' keyword")
				}
				return
			}

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
