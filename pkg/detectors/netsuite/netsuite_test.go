package netsuite

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validConsumerKey      = "3WaMEd0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15"
	invalidConsumerKey    = "3Wa?Ed0KQtHSU7b24HEd79RZzSpMOfMdMUpIaXjq83DbNHVosCVrEVDxKiEQzT15"
	validConsumerSecret   = "5BZ70LfNshsJkDya1XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD"
	invalidConsumerSecret = "5BZ70LfNshsJkDya?XaD8bMqtPWlOa2o1yKCk0H2DxnjtoaJKIcAw75GdI6zRaRD"
	validTokenKey         = "KeYcG56ViFDleXPFJuEQ5CAGSJn7o2WDa5iGvLIvVBqZj5rMkaWFmzkp4bveJa74"
	invalidTokenKey       = "KeYcG56ViFDleXPFJuEQ5CAGSJn7o2WD?5iGvLIvVBqZj5rMkaWFmzkp4bveJa74"
	validTokenSecret      = "GGQUdyYOGDfDImJWCz4Kufk2GevaIDuVv83kIa9zCRuXIDLB4oh2eVDVPmsaSai2"
	invalidTokenSecret    = "GGQUdyYOGDfDImJWCz4Kufk2Ge?aIDuVv83kIa9zCRuXIDLB4oh2eVDVPmsaSai2"
	validAccountID        = "x1L2_BXo"
	invalidAccountID      = "x1L2?BXo"
	keyword               = "netsuite"
	inputFormat           = `%s id - '%s'
consumer - '%s' consumer - '%s'
token - '%s' token - '%s'`
	outputPair1 = validConsumerKey + validConsumerSecret
	outputPair2 = validConsumerSecret + validConsumerKey
)

func TestNetsuite_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword netsuite",
			input: fmt.Sprintf(inputFormat, keyword, validAccountID, validConsumerKey, validConsumerSecret, validTokenKey, validTokenSecret),
			want:  []string{outputPair1, outputPair2, outputPair1, outputPair2},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf(inputFormat, keyword, invalidAccountID, invalidConsumerKey, invalidConsumerSecret, invalidTokenKey, invalidTokenSecret),
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
