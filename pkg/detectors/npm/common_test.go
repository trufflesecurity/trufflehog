package npm

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

type npmPatternTestCase struct {
	input    string
	expected string
}

func testPattern(t *testing.T, d detectors.Detector, tests map[string]npmPatternTestCase) {
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			chunkSpecificDetectors := make(map[ahocorasick.DetectorKey]detectors.Detector, 2)
			ahoCorasickCore.PopulateMatchingDetectors(test.input, chunkSpecificDetectors)
			if len(chunkSpecificDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) == 0 {
				if test.expected != "" {
					t.Error("did not receive result")
				}
				return
			}

			actual := string(results[0].Raw)
			if test.expected != actual {
				t.Errorf("expected '%s' != actual '%s'", test.expected, actual)
			}
		})
	}
}
