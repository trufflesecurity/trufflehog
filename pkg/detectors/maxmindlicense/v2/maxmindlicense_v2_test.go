package maxmindlicense

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"testing"
)

func TestMaxMind_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "key in URL",
			input: `#cd /home/xtreamcodes/iptv_xtream_codes/
#wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=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&suffix=tar.gz" -qO /home/xtreamcodes/iptv_xtream_codes/GeoLite2-City.mmdb.tar.gz
#tar -xf /home/xtreamcodes/iptv_xtream_codes/GeoLite2-City.mmdb.tar.gz`,
			want: []string{"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"},
		},
		{
			name: "ENV VAR",
			input: `BASE_URL=https://plausible.example.com
SECRET_KEY_BASE=GLVzDZW04FzuS1gMcmBRVhwgd4Gu9YmSl/k/TqfTUXti7FLBd7aflXeQDdwCj6Cz
TOTP_VAULT_KEY=dsxvbn3jxDd16az2QpsX5B8O+llxjQ2SJE2i5Bzx38I=
MAXMIND_LICENSE_KEY=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
MAXMIND_EDITION=GeoLite2-City
GOOGLE_CLIENT_ID=...`,
			want: []string{"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"},
		},
		{
			name: "Random .conf",
			input: `# LicenseKey is from your MaxMind account
LicenseKey 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`,
			want: []string{"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"},
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
