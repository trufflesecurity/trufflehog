package decoders

import (
	"bytes"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type UTF8 struct{}

func (d *UTF8) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: detectorspb.DecoderType_PLAIN}

	if !utf8.Valid(chunk.Data) {
		chunk.Data = extractSubstrings(chunk.Data)
		return decodableChunk
	}

	return decodableChunk
}

// extractSubstrings performs similarly to the strings binutil,
// extacting contigous portions of printable characters that we care
// about from some bytes
func extractSubstrings(b []byte) []byte {

	field := make([]byte, len(b))
	fieldLen := 0
	buf := &bytes.Buffer{}
	for i, c := range b {
		if isValidByte(c) {
			field[fieldLen] = c
			fieldLen++
		} else {
			if fieldLen > 5 {
				buf.Write(field[:fieldLen])
			}
			fieldLen = 0
		}

		if i == len(b)-1 && fieldLen > 5 {
			buf.Write(field[:fieldLen])
		}
	}

	return buf.Bytes()
}

func isValidByte(c byte) bool {
	// https://www.rapidtables.com/code/text/ascii-table.html
	// split on anything that is not ascii space through tilde
	return c > 31 && c < 127
}
