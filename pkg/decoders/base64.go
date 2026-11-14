package decoders

import (
	"bytes"
	"encoding/base64"
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
	// Standard and URL-safe alphabets, each with and without padding.
	b64Encodings = []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
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
		// A string that several encodings accept decodes to the same bytes with each of them.
		for _, enc := range b64Encodings {
			dec, err := enc.DecodeString(str)
			if err == nil && len(dec) > 0 && isASCII(dec) {
				decodedSubstrings[str] = dec
				break
			}
		}
	}

	if len(decodedSubstrings) > 0 {
		var result bytes.Buffer
		result.Grow(len(chunk.Data))

		start := 0
		for _, encoded := range encodedSubstrings {
			if decoded, ok := decodedSubstrings[encoded]; ok {
				end := bytes.Index(chunk.Data[start:], []byte(encoded))
				if end != -1 {
					result.Write(chunk.Data[start : start+end])
					result.Write(decoded)
					start += end + len(encoded)
				}
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

func getSubstringsOfCharacterSet(data []byte, threshold int, charsetMapping [128]bool, endChars string) []string {
	if len(data) == 0 {
		return nil
	}

	count := 0
	substringsCount := 0

	// Determine the number of substrings that will be returned.
	// Pre-allocate the slice to avoid reallocations.
	for _, char := range data {
		if char < 128 && charsetMapping[char] {
			count++
		} else {
			if count > threshold {
				substringsCount++
			}
			count = 0
		}
	}
	if count > threshold {
		substringsCount++
	}

	count = 0
	start := 0
	substrings := make([]string, 0, substringsCount)

	for i, char := range data {
		if char < 128 && charsetMapping[char] {
			if count == 0 {
				start = i
			}
			count++
		} else {
			if count > threshold {
				substrings = appendB64Substring(data, start, count, substrings, endChars)
			}
			count = 0
		}
	}

	if count > threshold {
		substrings = appendB64Substring(data, start, count, substrings, endChars)
	}

	return substrings
}

func appendB64Substring(data []byte, start, count int, substrings []string, endChars string) []string {
	substring := bytes.TrimLeft(data[start:start+count], endChars)
	if idx := bytes.IndexByte(bytes.TrimRight(substring, endChars), '='); idx != -1 {
		substrings = append(substrings, string(substring[idx+1:]))
	} else {
		substrings = append(substrings, string(substring))
	}
	return substrings
}
