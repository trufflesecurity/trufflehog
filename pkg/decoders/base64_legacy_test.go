package decoders

import (
	"bytes"
	"encoding/base64"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"unicode"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// The previous Base64 decoder, kept to check the current one gives the same output.

var legacyB64CharsetMapping [128]bool

func init() {
	for _, char := range b64Charset {
		legacyB64CharsetMapping[char] = true
	}
}

func legacyBase64FromChunk(chunk *sources.Chunk) *DecodableChunk {
	decodableChunk := &DecodableChunk{Chunk: chunk, DecoderType: detectorspb.DecoderType_BASE64}
	encodedSubstrings := legacyGetSubstringsOfCharacterSet(chunk.Data, 20, legacyB64CharsetMapping, b64EndChars)
	decodedSubstrings := make(map[string][]byte)

	for _, str := range encodedSubstrings {
		dec, err := base64.StdEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 && legacyIsASCII(dec) {
			decodedSubstrings[str] = dec
		}

		dec, err = base64.RawURLEncoding.DecodeString(str)
		if err == nil && len(dec) > 0 && legacyIsASCII(dec) {
			decodedSubstrings[str] = dec
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

func legacyIsASCII(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func legacyGetSubstringsOfCharacterSet(data []byte, threshold int, charsetMapping [128]bool, endChars string) []string {
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
				substrings = legacyAppendB64Substring(data, start, count, substrings, endChars)
			}
			count = 0
		}
	}

	if count > threshold {
		substrings = legacyAppendB64Substring(data, start, count, substrings, endChars)
	}

	return substrings
}

func legacyAppendB64Substring(data []byte, start, count int, substrings []string, endChars string) []string {
	substring := bytes.TrimLeft(data[start:start+count], endChars)
	if idx := bytes.IndexByte(bytes.TrimRight(substring, endChars), '='); idx != -1 {
		substrings = append(substrings, string(substring[idx+1:]))
	} else {
		substrings = append(substrings, string(substring))
	}
	return substrings
}

func assertSameAsLegacy(t *testing.T, data []byte) {
	t.Helper()
	got := (&Base64{}).FromChunk(&sources.Chunk{Data: bytes.Clone(data)})
	want := legacyBase64FromChunk(&sources.Chunk{Data: bytes.Clone(data)})
	if (got == nil) != (want == nil) {
		t.Fatalf("nil mismatch for %q: got nil=%v, want nil=%v", data, got == nil, want == nil)
	}
	if got != nil && !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("output mismatch for %q:\n got: %q\nwant: %q", data, got.Data, want.Data)
	}
}

func randomB64ishInput(r *rand.Rand) []byte {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_="
	const separators = " \n\t.,:;\"'(){}[]<>\x00\xff\xc3"
	var buf bytes.Buffer
	for buf.Len() < r.IntN(400)+1 {
		switch r.IntN(4) {
		case 0:
			plain := make([]byte, r.IntN(60)+1)
			for i := range plain {
				plain[i] = byte(r.IntN(95) + 32)
			}
			if r.IntN(2) == 0 {
				buf.WriteString(base64.StdEncoding.EncodeToString(plain))
			} else {
				buf.WriteString(base64.RawURLEncoding.EncodeToString(plain))
			}
		case 1:
			for range r.IntN(50) + 1 {
				buf.WriteByte(charset[r.IntN(len(charset))])
			}
		default:
			buf.WriteByte(separators[r.IntN(len(separators))])
		}
	}
	return buf.Bytes()
}

func TestBase64_MatchesLegacy_Random(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 200_000 {
		assertSameAsLegacy(t, randomB64ishInput(r))
	}
}

func TestBase64_MatchesLegacy_BenchmarkData(t *testing.T) {
	for name, data := range detectors.MustGetBenchmarkData() {
		t.Run(name, func(t *testing.T) { assertSameAsLegacy(t, data) })
	}
}

func TestBase64_MatchesLegacy_SourceFiles(t *testing.T) {
	files, err := filepath.Glob("../*/*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(data); i += 10 * 1024 {
			assertSameAsLegacy(t, data[i:min(i+10*1024, len(data))])
		}
	}
}

func FuzzBase64_MatchesLegacy(f *testing.F) {
	f.Add([]byte(`token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`))
	f.Add([]byte(`a=bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q==b`))
	f.Add([]byte(`bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q_-x bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`))
	f.Fuzz(func(t *testing.T, data []byte) {
		assertSameAsLegacy(t, data)
	})
}
