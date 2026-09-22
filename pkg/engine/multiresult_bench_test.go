package engine

import (
	"fmt"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Measures the per-chunk cost of N results sharing one secret on a decoded chunk,
// which is the case AssignDuplicateLineOffsets exists for.
func BenchmarkFragmentLineOffset_MultiResult(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		secret := []byte("synthetic-secret-value-123456")
		var original, decoded []byte
		for i := 0; len(original) < sources.DefaultChunkSize; i++ {
			original = append(original, fmt.Sprintf("<p class=\"row\">line%d</p>\n", i)...)
			decoded = append(decoded, fmt.Sprintf("line%d\n", i)...)
		}
		original = append(original, "<p>"...)
		original = append(original, secret...)
		original = append(original, "</p>\n"...)
		decoded = append(decoded, secret...)
		decoded = append(decoded, '\n')
		chunk := &sources.Chunk{Data: decoded, OriginalData: original}

		b.Run(fmt.Sprintf("results=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for j := 0; j < n; j++ {
					_, _ = FragmentLineOffset(chunk, &detectors.Result{Raw: secret})
				}
			}
		})
	}
}
