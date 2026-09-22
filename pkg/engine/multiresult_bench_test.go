package engine

import (
	"fmt"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// mapChunkResults maps every result of one chunk to its source line the way the
// production result loop does. The implementation differs per branch: the
// performance branch shares one occurrence index across the batch.
var mapChunkResults = func(chunk *sources.Chunk, results []*detectors.Result) {
	idx := newChunkOccurrenceIndex()
	for _, r := range results {
		_, _ = fragmentLineOffset(chunk, r, idx)
	}
}

// Measures the per-chunk cost of mapping N results sharing one secret on a
// decoded chunk, which is the case AssignDuplicateLineOffsets exists for.
func BenchmarkFragmentLineOffset_MultiResult(b *testing.B) {
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

	var results []*detectors.Result
	for range 40 {
		results = append(results, &detectors.Result{Raw: secret})
	}

	for _, n := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("results=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				mapChunkResults(chunk, results[:n])
			}
		})
	}
}

// Same shape as the ambiguous case: the secret also occurs in markup the decoder
// dropped, so occurrences must be told apart by their surroundings.
func BenchmarkFragmentLineOffset_MultiResultAmbiguous(b *testing.B) {
	secret := []byte("synthetic-secret-value-123456")
	original := []byte("<div class=\"synthetic-secret-value-123456\">\n")
	var decoded []byte
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

	var results []*detectors.Result
	for range 8 {
		results = append(results, &detectors.Result{Raw: secret})
	}

	for _, n := range []int{1, 8} {
		b.Run(fmt.Sprintf("results=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				mapChunkResults(chunk, results[:n])
			}
		})
	}
}
