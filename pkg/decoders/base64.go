package decoders

import (
	"bytes"
	"encoding/base64"
	"sort"
	"unicode"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type (
	Base64 struct{}
)

var (
	b64Charset  = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")
	b64EndChars = "+/-_="
	// Given characters are mostly ASCII, we can use a simple array to map.
	b64CharsetMapping [128]bool
)

func init() {
	// Build an array of all the characters in the base64 charset.
	for _, char := range b64Charset {
		b64CharsetMapping[char] = true
	}
}

func (d *Base64) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_BASE64
}

func (d *Base64) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
	encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndChars)
	decodedSubstrings := make(map[string][]byte)

	for _, str := range encodedSubstrings {
		dec, err := base64.StdEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 && isASCII(dec) {
			decodedSubstrings[str] = dec
		}

		dec, err = base64.RawURLEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 && isASCII(dec) {
			decodedSubstrings[str] = dec
		}
	}

	if len(decodedSubstrings) > 0 {
		// Build a position map and sort encoded strings by their position in the original data.
		// This ensures we process the data in a single forward pass, handling each encoded string
		// in order of appearance. By sorting first, we guarantee sequential processing and avoid
		// potential backward scans through already processed data.
		positionMap := make(map[string]int, len(encodedSubstrings))
		remaining := chunk.Data
		pos := 0

		for _, encoded := range encodedSubstrings {
			if idx := bytes.Index(remaining, []byte(encoded)); idx != -1 {
				positionMap[encoded] = pos + idx
				pos += idx
				remaining = remaining[idx+len(encoded):]
			}
		}

		var result bytes.Buffer
		result.Grow(len(chunk.Data))
		start := 0
		// Sort encodedSubstrings by their positions for sequential processing.
		sortedSubstrings := make([]string, 0, len(positionMap))
		for encoded := range positionMap {
			sortedSubstrings = append(sortedSubstrings, encoded)
		}
		sort.Slice(sortedSubstrings, func(i, j int) bool {
			return positionMap[sortedSubstrings[i]] < positionMap[sortedSubstrings[j]]
		})

		// Process in sequential order.
		for _, encoded := range sortedSubstrings {
			if decoded, ok := decodedSubstrings[encoded]; ok {
				pos := positionMap[encoded]
				result.Write(chunk.Data[start:pos])
				result.Write(decoded)
				start = pos + len(encoded)
			}
		}

		result.Write(chunk.Data[start:])
		chunk.Data = result.Bytes()
		return decodableChunk
	}

	return nil
}

func isASCII(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// getSubstringsOfCharacterSet extracts base64-encoded substrings
// from byte data that meet the threshold.
func getSubstringsOfCharacterSet(data []byte, threshold int, charsetMapping [128]bool, endChars string) []string {
	if len(data) == 0 {
		return nil
	}

	// initialSubstringsCapacity is set to 16 as a practical optimization,
	// balancing memory usage with the typical number of base64-encoded
	// strings found in common input data. (this could be tuned further)
	const initialSubstringsCapacity = 16
	substrings := make([]string, 0, initialSubstringsCapacity)

	count := 0
	start := 0

	for i := range data {
		char := data[i]
		isValid := char < 128 && charsetMapping[char]

		if isValid {
			if count == 0 {
				start = i
			}
			count++
			continue
		}

		if count > threshold {
			substrings = appendB64Substring(data, start, count, substrings, endChars)
		}
		count = 0
	}

	if count > threshold {
		substrings = appendB64Substring(data, start, count, substrings, endChars)
	}

	return substrings
}

// appendB64Substring processes and appends a base64 substring to the result slice.
// It handles both standard and URL-safe base64 encodings, preserving padding characters
// and special characters like underscores.
func appendB64Substring(data []byte, start, count int, substrings []string, endChars string) []string {
	left := start
	right := start + count - 1

	// Trim left end chars except underscore.
	for left < right && bytes.IndexByte([]byte(endChars), data[left]) != -1 && data[left] != '_' {
		left++
	}

	// Trim right end chars except underscore and equals.
	for right > left && bytes.IndexByte([]byte(endChars), data[right]) != -1 {
		if data[right] == '=' || data[right] == '_' {
			break
		}
		right--
	}

	// Find equals sign in the middle if present.
	for i := left; i < right; i++ {
		if data[i] == '=' {
			left = i + 1
			break
		}
	}

	// Only append if we have valid data after trimming.
	if right >= left {
		substrings = append(substrings, string(data[left:right+1]))
	}

	return substrings
}
