package rsasecurid

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

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
