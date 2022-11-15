package decoders

import (
	"bytes"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type UTF8 struct{}

func (d *UTF8) FromChunk(chunk *sources.Chunk) *sources.Chunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	if !utf8.Valid(chunk.Data) {
		chunk.Data = extractSubstrings(chunk.Data)
		return chunk
	}

	return chunk
}

// extractSubstrings performs similarly to the strings binutil,
// extacting contigous portions of printable characters that we care
// about from some bytes
func extractSubstrings(b []byte) []byte {
	fields := bytes.FieldsFunc(b, func(r rune) bool {
		// https://www.rapidtables.com/code/text/ascii-table.html
		// split on anything that is not ascii space through tilde
		return !(r > 31 && r < 127)
	})

	keep := [][]byte{}
	for _, field := range fields {
		// Remove fields shorter than 6 characters.
		if bts := bytes.TrimSpace(field); len(bts) > 5 {
			keep = append(keep, bts)
		}
	}

	return bytes.Join(keep, []byte("\n"))
}
