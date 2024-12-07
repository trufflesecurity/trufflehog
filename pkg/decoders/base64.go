package decoders

import (
	"bytes"
	"encoding/base64"
	"unicode"
	"unsafe"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type (
	Base64 struct{}
)

var (
	b64Charset  = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")
	b64EndChars = "+/-_="

	b64CharsetMapping  [128]bool
	b64EndCharsMapping [128]bool
)

func init() {
	for _, char := range b64Charset {
		if char < 128 {
			b64CharsetMapping[char] = true
		}
	}
	for _, char := range b64EndChars {
		if char < 128 {
			b64EndCharsMapping[char] = true
		}
	}
}

func (d *Base64) Type() detectorspb.DecoderType {
	return detectorspb.DecoderType_BASE64
}

func (d *Base64) FromChunk(chunk *sources.Chunk) *DecodableChunk {
	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}
	candidates := getSubstringsOfCharacterSet(chunk.Data, 20, b64CharsetMapping, b64EndCharsMapping)

	if len(candidates) == 0 {
		return nil
	}

	var decodedCandidates []decodedCandidate
	for _, c := range candidates {
		data := chunk.Data[c.start:c.end]
		substring := bytesToString(data)

		// Heuristics: If substring contains '=', try StdEncoding first; otherwise, RawURLEncoding.
		// This avoids unnecessary decoding since:
		// 1. If a string contains '=', it's likely using standard base64 padding
		// 2. If a string can be decoded by both standard and URL-safe base64,
		//    both decodings would produce identical output (they only differ in
		//    how they encode '+/' vs '-_')
		// 3. Therefore, if we successfully decode with our first attempt, we can
		//    skip trying the other encoding
		var dec []byte
		if bytes.Contains(data, []byte("=")) {
			dec, _ = base64.StdEncoding.DecodeString(substring)
			if len(dec) == 0 {
				dec, _ = base64.RawURLEncoding.DecodeString(substring)
			}
		} else {
			dec, _ = base64.RawURLEncoding.DecodeString(substring)
			if len(dec) == 0 {
				dec, _ = base64.StdEncoding.DecodeString(substring)
			}
		}

		if len(dec) > 0 && isASCII(dec) {
			decodedCandidates = append(decodedCandidates, decodedCandidate{
				start:   c.start,
				end:     c.end,
				decoded: dec,
			})
		}
	}

	if len(decodedCandidates) == 0 {
		return nil
	}

	// Rebuild the chunk data
	var result bytes.Buffer
	result.Grow(len(chunk.Data))

	lastPos := 0
	for _, dc := range decodedCandidates {
		if dc.start > lastPos {
			result.Write(chunk.Data[lastPos:dc.start])
		}
		result.Write(dc.decoded)
		lastPos = dc.end
	}

	if lastPos < len(chunk.Data) {
		result.Write(chunk.Data[lastPos:])
	}

	chunk.Data = result.Bytes()
	return decodableChunk
}

func bytesToString(b []byte) string { return *(*string)(unsafe.Pointer(&b)) }

func isASCII(b []byte) bool {
	for _, c := range b {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

type candidate struct {
	start int
	end   int
}

type decodedCandidate struct {
	start   int
	end     int
	decoded []byte
}

func getSubstringsOfCharacterSet(data []byte, threshold int, charsetMapping [128]bool, endCharsMapping [128]bool) []candidate {
	if len(data) == 0 {
		return nil
	}

	count := 0
	substringsCount := 0
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

	if substringsCount == 0 {
		return nil
	}

	candidates := make([]candidate, 0, substringsCount)

	count = 0
	start := 0
	for i, char := range data {
		if char < 128 && charsetMapping[char] {
			if count == 0 {
				start = i
			}
			count++
		} else {
			if count > threshold {
				candidates = appendB64Substring(data, start, count, candidates, endCharsMapping)
			}
			count = 0
		}
	}
	// Handle trailing substring if needed.
	if count > threshold {
		candidates = appendB64Substring(data, start, count, candidates, endCharsMapping)
	}
	return candidates
}

func appendB64Substring(data []byte, start, count int, candidates []candidate, endCharsMapping [128]bool) []candidate {
	sub := data[start : start+count] // Original slice before trimming

	// Manually trim left.
	left := 0
	for left < len(sub) && sub[left] < 128 && endCharsMapping[sub[left]] {
		left++
	}
	substring := sub[left:] // substring after left trim
	substringLength := len(substring)

	// Manually trim right on 'substring'.
	right := substringLength - 1
	for right >= 0 && substring[right] < 128 && endCharsMapping[substring[right]] {
		right--
	}

	// If right < 0, everything got trimmed out.
	if right < 0 {
		// This matches the original behavior: if nothing remains after trimming, we don't add a candidate.
		return candidates
	}

	trimmedRight := substring[:right+1]
	idx := bytes.IndexByte(trimmedRight, '=')

	if idx != -1 {
		// Substring after '='.
		candidates = append(candidates, candidate{
			start: start + (count - substringLength) + idx + 1,
			end:   start + (count - substringLength) + substringLength,
		})
	} else {
		candidates = append(candidates, candidate{
			start: start + (count - substringLength),
			end:   start + (count - substringLength) + substringLength,
		})
	}
	return candidates
}
