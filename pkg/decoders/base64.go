package decoders

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type (
	Base64 struct{}
)

var (
	b64Charset        = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")
	b64EndChars       = "+/-_="
	b64CharsetMapping [256]bool
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
	encodedSubstrings := getSubstringsOfCharacterSet(chunk.Data, 20, &b64CharsetMapping, b64EndChars)
	decodedSubstrings := make(map[string][]byte)

	for _, str := range encodedSubstrings {
		// Skip decodes that are certain to fail.
		if len(str)%4 == 0 && !strings.ContainsAny(str, "-_") {
			dec, err := base64.StdEncoding.DecodeString(str)
			if err == nil && len(dec) > 0 && isASCII(dec) {
				decodedSubstrings[str] = dec
			}
		}

		if len(str)%4 != 1 && !strings.ContainsAny(str, "+/=") {
			dec, err := base64.RawURLEncoding.DecodeString(str)
			if err == nil && len(dec) > 0 && isASCII(dec) {
				decodedSubstrings[str] = dec
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

func getSubstringsOfCharacterSet(data []byte, threshold int, charsetMapping *[256]bool, endChars string) []string {
	if len(data) == 0 {
		return nil
	}

	var substrings []string
	count := 0
	start := 0

	for i, char := range data {
		if charsetMapping[char] {
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

func appendB64Substring(data []byte, start, count int, substrings []string, endChars string) []string {
	substring := bytes.TrimLeft(data[start:start+count], endChars)
	if idx := bytes.IndexByte(bytes.TrimRight(substring, endChars), '='); idx != -1 {
		substrings = append(substrings, string(substring[idx+1:]))
	} else {
		substrings = append(substrings, string(substring))
	}
	return substrings
}
