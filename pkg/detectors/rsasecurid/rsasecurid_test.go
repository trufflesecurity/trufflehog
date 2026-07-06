package rsasecurid

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// contextPatLiterals are the structural markers contextPat matches on. Each one
// must have a corresponding Keywords() entry, otherwise the Aho-Corasick
// prefilter drops inputs that only carry that marker before FromData ever runs.
var contextPatLiterals = []string{"TKNBatch", "TKNBasic", "sdtid"}

// TestRSASecurID_KeywordsCoverContextMarkers asserts that every structural
// marker recognised by contextPat is also advertised as a Keyword.
//
// GIVEN the detector's contextPat accepts <TKNBatch, <TKNBasic and .sdtid
// WHEN we compare those literals against Keywords()
// THEN each literal must be covered by a keyword the prefilter can match on.
func TestRSASecurID_KeywordsCoverContextMarkers(t *testing.T) {
	keywords := Scanner{}.Keywords()
	for _, literal := range contextPatLiterals {
		covered := false
		for _, kw := range keywords {
			// Keyword matching is case-insensitive; a keyword covers a literal
			// when it appears as a (case-insensitive) substring of that literal.
			if strings.Contains(strings.ToLower(literal), strings.ToLower(kw)) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf(
				"contextPat literal %q has no covering keyword in %v: a token whose only marker is %q is dropped by the Aho-Corasick prefilter and never scanned",
				literal, keywords, literal,
			)
		}
	}
}

// TestRSASecurID_TKNBasicOnlyTokenIsScanned reproduces the review-flagged bug:
// a token whose ONLY structural marker is <TKNBasic> (no <TKNBatch>, no literal
// "sdtid") must still be detected end-to-end through the real prefilter path.
//
// GIVEN a .sdtid blob whose only structural marker is <TKNBasic> with a valid
//
//	12-digit <SN> and a <Seed>
//
// WHEN it is scanned through the Aho-Corasick prefilter and then FromData
// THEN exactly one RSA SecurID result is returned.
func TestRSASecurID_TKNBasicOnlyTokenIsScanned(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	input := `<?xml version="1.0" encoding="UTF-8"?>
<TKNBasic>
  <SN>` + fakeSN + `</SN>
  <Seed>` + fakeSeedHex + `</Seed>
  <Digits>6</Digits>
  <Interval>60</Interval>
</TKNBasic>`

	// Guard the fixture: it must NOT carry the other markers, otherwise the test
	// would pass for the wrong reason.
	require.NotContains(t, input, "TKNBatch")
	require.NotContains(t, input, "sdtid")

	// The real prefilter must select this detector.
	matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(input))
	require.NotEmpty(t, matchedDetectors,
		"prefilter dropped a <TKNBasic>-only token; Keywords()=%v cannot match it", d.Keywords())

	results, err := d.FromData(context.Background(), false, []byte(input))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, fakeSN+":"+fakeSeedHex, string(results[0].RawV2))
}

// All serials and seeds below are synthetic, sequential, clearly-fake test
// values. They contain no real RSA SecurID token material.
const (
	fakeSN      = "531234567890"
	fakeSeedHex = "0102030405060708090A0B0C0D0E0F10"
	fakeSN2     = "539876543210"
	fakeSeedB64 = "AQ4Hh0qN1k2l3m4n5o6p7w=="
)

func TestRSASecurID_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - sdtid XML with hex seed",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<TKNBatch>
  <TKN>
    <TKNBasic>
      <SN>` + fakeSN + `</SN>
      <Seed>` + fakeSeedHex + `</Seed>
      <Digits>6</Digits>
      <Interval>60</Interval>
    </TKNBasic>
  </TKN>
</TKNBatch>`,
			want: []string{fakeSN + ":" + fakeSeedHex},
		},
		{
			name: "valid pattern - sdtid XML with base64 (encrypted) seed",
			input: `<TKNBatch>
  <TKNBasic>
    <SN>` + fakeSN2 + `</SN>
    <Seed>` + fakeSeedB64 + `</Seed>
  </TKNBasic>
</TKNBatch>`,
			want: []string{fakeSN2 + ":" + fakeSeedB64},
		},
		{
			name: "invalid pattern - SN present but no Seed",
			input: `<TKNBatch>
  <TKNBasic>
    <SN>` + fakeSN + `</SN>
    <Digits>6</Digits>
  </TKNBasic>
</TKNBatch>`,
			want: nil,
		},
		{
			name: "invalid pattern - Seed present but no SN",
			input: `<TKNBatch>
  <TKNBasic>
    <Seed>` + fakeSeedHex + `</Seed>
  </TKNBasic>
</TKNBatch>`,
			want: nil,
		},
		{
			name: "invalid pattern - wrong element names",
			input: `<Batch>
  <Token>
    <Serial>` + fakeSN + `</Serial>
    <Key>` + fakeSeedHex + `</Key>
  </Token>
</Batch>`,
			want: nil,
		},
		{
			name: "invalid pattern - seed too short",
			input: `<TKNBatch>
  <TKNBasic>
    <SN>` + fakeSN + `</SN>
    <Seed>0102030405</Seed>
  </TKNBasic>
</TKNBatch>`,
			want: nil,
		},
		{
			name: "invalid pattern - serial wrong length",
			input: `<TKNBatch>
  <TKNBasic>
    <SN>12345</SN>
    <Seed>` + fakeSeedHex + `</Seed>
  </TKNBasic>
</TKNBatch>`,
			want: nil,
		},
		{
			name: "invalid pattern - no TKNBatch keyword",
			input: `<config>
    <SN>` + fakeSN + `</SN>
    <Seed>` + fakeSeedHex + `</Seed>
</config>`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))

			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf(
					"test %q failed: expected keywords %v to be found in the input",
					test.name,
					d.Keywords(),
				)
				return
			}

			results, err := d.FromData(
				context.Background(),
				false,
				[]byte(test.input),
			)
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf(
					"mismatch in result count: expected %d, got %d",
					len(test.want),
					len(results),
				)
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
