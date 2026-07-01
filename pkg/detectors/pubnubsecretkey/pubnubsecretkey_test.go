package pubnubsecretkey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validSecKey  = "sec-c-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	validPubKey  = "pub-c-12345678-abcd-ef01-2345-6789abcdef01"
	validSubKey  = "sub-c-12345678-abcd-ef01-2345-6789abcdef01"
	validSecKey2 = "sec-c-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	validPubKey2 = "pub-c-98765432-dcba-10fe-5432-fedcba987654"
	validSubKey2 = "sub-c-98765432-dcba-10fe-5432-fedcba987654"
)

func TestPubNubSecretKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid sec+pub+sub triple",
			input: fmt.Sprintf("secret=%s publish=%s subscribe=%s", validSecKey, validPubKey, validSubKey),
			want:  []string{validPubKey + "/" + validSubKey + "/" + validSecKey},
		},
		{
			name: "two sec keys with one pub+sub - produces two results",
			input: fmt.Sprintf("secret=%s secret2=%s publish=%s subscribe=%s",
				validSecKey, validSecKey2, validPubKey, validSubKey),
			want: []string{
				validPubKey + "/" + validSubKey + "/" + validSecKey,
				validPubKey + "/" + validSubKey + "/" + validSecKey2,
			},
		},
		{
			name: "two complete triples - produces four combinations",
			input: fmt.Sprintf("secret=%s publish=%s subscribe=%s secret2=%s publish2=%s subscribe2=%s",
				validSecKey, validPubKey, validSubKey, validSecKey2, validPubKey2, validSubKey2),
			want: []string{
				validPubKey + "/" + validSubKey + "/" + validSecKey,
				validPubKey + "/" + validSubKey + "/" + validSecKey2,
				validPubKey2 + "/" + validSubKey + "/" + validSecKey,
				validPubKey2 + "/" + validSubKey + "/" + validSecKey2,
				validPubKey + "/" + validSubKey2 + "/" + validSecKey,
				validPubKey + "/" + validSubKey2 + "/" + validSecKey2,
				validPubKey2 + "/" + validSubKey2 + "/" + validSecKey,
				validPubKey2 + "/" + validSubKey2 + "/" + validSecKey2,
			},
		},
		{
			name:  "sec key only - no pub or sub present",
			input: fmt.Sprintf("secret=%s", validSecKey),
			want:  []string{},
		},
		{
			name:  "sec and pub present but no sub",
			input: fmt.Sprintf("secret=%s publish=%s", validSecKey, validPubKey),
			want:  []string{},
		},
		{
			name:  "sec and sub present but no pub",
			input: fmt.Sprintf("secret=%s subscribe=%s", validSecKey, validSubKey),
			want:  []string{},
		},
		{
			name:  "invalid sec key - wrong prefix char count",
			input: fmt.Sprintf("secret=sec-c-TOOSHORT publish=%s subscribe=%s", validPubKey, validSubKey),
			want:  []string{},
		},
		{
			name:  "invalid sec key - contains invalid base64 chars",
			input: fmt.Sprintf("secret=sec-c-%s publish=%s subscribe=%s", "AAAA!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", validPubKey, validSubKey),
			want:  []string{},
		},
		{
			name:  "invalid pub key pattern",
			input: fmt.Sprintf("secret=%s publish=pub-c-NOTAUUID subscribe=%s", validSecKey, validSubKey),
			want:  []string{},
		},
		{
			name:  "invalid sub key pattern",
			input: fmt.Sprintf("secret=%s publish=%s subscribe=sub-c-NOTAUUID", validSecKey, validPubKey),
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf("keywords '%v' not matched by input", d.Keywords())
				}
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
