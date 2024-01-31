package decoders

import (
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type EscapedUnicode struct{}

var _ Decoder = (*EscapedUnicode)(nil)

// It might be advantageous to limit these to a subset of acceptable characters, similar to base64.
// https://dencode.com/en/string/unicode-escape
//
// Another format worth considering is `U+1234`
var escapePat = regexp.MustCompile(`(?i:\\{1,2}u)([a-fA-F0-9]{4})`)

func (d *EscapedUnicode) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 || !escapePat.Match(chunk.Data) {
		return nil
	}

	chunk.Data = decodeUnicode(chunk.Data)
	decodableChunk := &DecodableChunk{
		DecoderType: detectorspb.DecoderType_ESCAPED_UNICODE,
		Chunk:       chunk,
	}

	return decodableChunk
}

// Unicode characters are encoded as 1 to 4 bytes per rune.
const maxBytesPerRune = 4

func decodeUnicode(input []byte) []byte {
	// Find all Unicode escape sequences in the input byte slice
	indices := escapePat.FindAllSubmatchIndex(input, -1)

	// Iterate over found indices in reverse order to avoid modifying the slice length
	utf8Bytes := make([]byte, maxBytesPerRune)
	for i := len(indices) - 1; i >= 0; i-- {
		matches := indices[i]
		startIndex := matches[0]
		hexStartIndex := matches[2]
		endIndex := matches[3]

		// Extract the hexadecimal value from the escape sequence
		hexValue := string(input[hexStartIndex:endIndex])

		// Parse the hexadecimal value to an integer
		unicodeInt, err := strconv.ParseInt(hexValue, 16, 32)
		if err != nil {
			// If there's an error, continue to the next escape sequence
			continue
		}

		// Convert the Unicode code point to a UTF-8 representation
		utf8Len := utf8.EncodeRune(utf8Bytes, rune(unicodeInt))

		// Replace the escape sequence with the UTF-8 representation
		input = append(input[:startIndex], append(utf8Bytes[:utf8Len], input[endIndex:]...)...)
	}

	return input
}
