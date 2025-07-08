package decoders

import (
	"bytes"
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
var (
	// Standard Unicode notation.
	//https://unicode.org/standard/principles.html
	codePointPat = regexp.MustCompile(`\bU\+([a-fA-F0-9]{4}).?`)

	// Common escape sequence used in programming languages.
	escapePat = regexp.MustCompile(`(?i:\\{1,2}u)([a-fA-F0-9]{4})`)

	// Additional Unicode escape formats from dencode.com

	// \u{X} format - Rust, Swift, some JS, etc. (variable length hex in braces)
	braceEscapePat = regexp.MustCompile(`\\u\{([a-fA-F0-9]{1,6})\}`)

	// \U00XXXXXX format - Python, etc. (8-digit format for non-BMP characters)
	longEscapePat = regexp.MustCompile(`\\U([a-fA-F0-9]{8})`)

	// \x{X} format - Perl (variable length hex in braces)
	perlEscapePat = regexp.MustCompile(`\\x\{([a-fA-F0-9]{1,6})\}`)

	// \X format - CSS (hex without padding). Go's regexp (RE2) has no look-ahead, so we
	// include the delimiter (whitespace, another backslash, or end-of-string) in the
	// match using a non-capturing group. The delimiter is later re-inserted by the
	// decoder when necessary.
	cssEscapePat = regexp.MustCompile(`\\([a-fA-F0-9]{1,6})(?:\s|\\|$)`)

	// &#xX; format - HTML/XML (hex with semicolon)
	htmlEscapePat = regexp.MustCompile(`&#x([a-fA-F0-9]{1,6});`)

	// %uXXXX format - Percent-encoding (non-standard)
	percentEscapePat = regexp.MustCompile(`%u([a-fA-F0-9]{4})`)

	// // 0xX format - Hexadecimal notation with space separation
	// Note: Commenting out for now due to high memory overhead. Review ways to handle this.
	// hexEscapePat = regexp.MustCompile(`0x([a-fA-F0-9]{1,6})(?:\s|$)`)
)

func (d *EscapedUnicode) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_ESCAPED_UNICODE
}

func (d *EscapedUnicode) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil
	}

	var (
		// Necessary to avoid data races.
		chunkData = bytes.Clone(chunk.Data)
		matched   = false
	)

	// Process patterns in priority order - more specific patterns first
	// This prevents conflicts where multiple patterns match the same input

	// Long escape format (8 hex digits) - highest priority
	if longEscapePat.Match(chunkData) {
		matched = true
		chunkData = decodeLongEscape(chunkData)
	} else if braceEscapePat.Match(chunkData) {
		matched = true
		chunkData = decodeBraceEscape(chunkData)
	} else if perlEscapePat.Match(chunkData) {
		matched = true
		chunkData = decodePerlEscape(chunkData)
	} else if htmlEscapePat.Match(chunkData) {
		matched = true
		chunkData = decodeHtmlEscape(chunkData)
	} else if percentEscapePat.Match(chunkData) {
		matched = true
		chunkData = decodePercentEscape(chunkData)
	} else if escapePat.Match(chunkData) {
		matched = true
		chunkData = decodeEscaped(chunkData)
	} else if codePointPat.Match(chunkData) {
		matched = true
		chunkData = decodeCodePoint(chunkData)
	} else if cssEscapePat.Match(chunkData) {
		matched = true
		chunkData = decodeCssEscape(chunkData)
		// } else if hexEscapePat.Match(chunkData) {
		// 	matched = true
		// 	chunkData = decodeHexEscape(chunkData)
	}

	if matched {
		return &DecodableChunk{
			DecoderType: d.Type(),
			Chunk: &sources.Chunk{
				Data:           chunkData,
				SourceName:     chunk.SourceName,
				SourceID:       chunk.SourceID,
				JobID:          chunk.JobID,
				SecretID:       chunk.SecretID,
				SourceMetadata: chunk.SourceMetadata,
				SourceType:     chunk.SourceType,
				Verify:         chunk.Verify,
			},
		}
	} else {
		return nil
	}
}

// Unicode characters are encoded as 1 to 4 bytes per rune.
const maxBytesPerRune = 4
const spaceChar = byte(' ')

// decodeWithPattern replaces escape sequences matched by re with their UTF-8
// equivalents. The regex *must* have the first capturing group contain the
// hexadecimal code-point digits. Any invalid value (> 0x10FFFF or parse error)
// is skipped. The replacement walks matches in reverse order to avoid index
// shifts.
func decodeWithPattern(input []byte, re *regexp.Regexp) []byte {
	indices := re.FindAllSubmatchIndex(input, -1)
	if len(indices) == 0 {
		return input
	}

	utf8Bytes := make([]byte, maxBytesPerRune)
	for i := len(indices) - 1; i >= 0; i-- {
		m := indices[i]
		start, end := m[0], m[1]
		hexStart, hexEnd := m[2], m[3]

		cp, err := strconv.ParseUint(string(input[hexStart:hexEnd]), 16, 32)
		if err != nil || cp > 0x10FFFF {
			continue
		}

		utf8Len := utf8.EncodeRune(utf8Bytes, rune(cp))
		input = append(input[:start], append(utf8Bytes[:utf8Len], input[end:]...)...)
	}
	return input
}

func decodeCodePoint(input []byte) []byte {
	// Find all Unicode escape sequences in the input byte slice
	indices := codePointPat.FindAllSubmatchIndex(input, -1)

	// Iterate over found indices in reverse order to avoid modifying the slice length
	utf8Bytes := make([]byte, maxBytesPerRune)
	for i := len(indices) - 1; i >= 0; i-- {
		matches := indices[i]

		startIndex := matches[0]
		endIndex := matches[1]
		hexStartIndex := matches[2]
		hexEndIndex := matches[3]

		// If the input is like `U+1234 U+5678` we should replace `U+1234 `.
		// Otherwise, we should only replace `U+1234`.
		if endIndex != hexEndIndex && input[endIndex-1] != spaceChar {
			endIndex = endIndex - 1
		}

		// Extract the hexadecimal value from the escape sequence
		hexValue := string(input[hexStartIndex:hexEndIndex])

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

func decodeEscaped(input []byte) []byte {
	return decodeWithPattern(input, escapePat)
}

// decodeBraceEscape handles \u{X} format - Rust, Swift, some JS, etc.
func decodeBraceEscape(input []byte) []byte {
	return decodeWithPattern(input, braceEscapePat)
}

// decodeLongEscape handles \U00XXXXXX format - Python, etc.
func decodeLongEscape(input []byte) []byte {
	return decodeWithPattern(input, longEscapePat)
}

// decodePerlEscape handles \x{X} format - Perl
func decodePerlEscape(input []byte) []byte {
	return decodeWithPattern(input, perlEscapePat)
}

// decodeCssEscape handles \X format - CSS (hex without padding, with space delimiter or end of string or next hex sequence)
func decodeCssEscape(input []byte) []byte {
	return decodeWithPattern(input, cssEscapePat)
}

// decodeHtmlEscape handles &#xX; format - HTML/XML
func decodeHtmlEscape(input []byte) []byte {
	return decodeWithPattern(input, htmlEscapePat)
}

// decodePercentEscape handles %uXXXX format - Percent-encoding (non-standard)
func decodePercentEscape(input []byte) []byte {
	return decodeWithPattern(input, percentEscapePat)
}

// decodeHexEscape handles 0xX format - Hexadecimal notation with space separation
// func decodeHexEscape(input []byte) []byte {
// 	// This format requires consecutive 0xNN sequences to be considered for decoding
// 	// We'll look for patterns of multiple consecutive hex values
// 	hexPattern := regexp.MustCompile(`(?:0x[a-fA-F0-9]{1,2}(?:\s+|$))+`)

// 	matches := hexPattern.FindAll(input, -1)
// 	if len(matches) == 0 {
// 		return input
// 	}

// 	result := input
// 	for _, match := range matches {
// 		// Extract individual hex values
// 		individualHex := regexp.MustCompile(`0x([a-fA-F0-9]{1,2})`)
// 		hexMatches := individualHex.FindAllSubmatch(match, -1)

// 		// Only decode if we have multiple consecutive hex values (likely to be a Unicode string)
// 		if len(hexMatches) < 3 {
// 			continue
// 		}

// 		var decoded []byte
// 		for _, hexMatch := range hexMatches {
// 			hexValue := string(hexMatch[1])
// 			if len(hexValue) == 1 {
// 				hexValue = "0" + hexValue // Pad single digit hex values
// 			}

// 			unicodeInt, err := strconv.ParseUint(hexValue, 16, 32)
// 			if err != nil || unicodeInt > 0x10FFFF {
// 				break
// 			}

// 			if unicodeInt <= 0x7F {
// 				// ASCII character
// 				decoded = append(decoded, byte(unicodeInt))
// 			} else {
// 				// Unicode character
// 				utf8Bytes := make([]byte, maxBytesPerRune)
// 				utf8Len := utf8.EncodeRune(utf8Bytes, rune(unicodeInt))
// 				decoded = append(decoded, utf8Bytes[:utf8Len]...)
// 			}
// 		}

// 		// Replace the original sequence with decoded bytes
// 		result = bytes.Replace(result, match, decoded, 1)
// 	}

// 	return result
// }
