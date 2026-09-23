package decoders

import (
	"bytes"
	"math/rand"
	"strconv"
	"testing"
	"unicode/utf8"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// legacyCodePointPat is main's pattern, word boundary and all.
var legacyCodePointPat = regexp.MustCompile(`\bU\+([a-fA-F0-9]{4}).?`)

// legacyDecodeCodePoint is main's decodeCodePoint verbatim, driven by the
// boundary-carrying pattern.
func legacyDecodeCodePoint(input []byte) []byte {
	indices := legacyCodePointPat.FindAllSubmatchIndex(input, -1)
	utf8Bytes := make([]byte, maxBytesPerRune)
	for i := len(indices) - 1; i >= 0; i-- {
		matches := indices[i]
		startIndex, endIndex := matches[0], matches[1]
		hexStartIndex, hexEndIndex := matches[2], matches[3]
		if endIndex != hexEndIndex && input[endIndex-1] != spaceChar {
			endIndex = endIndex - 1
		}
		unicodeInt, err := strconv.ParseInt(string(input[hexStartIndex:hexEndIndex]), 16, 32)
		if err != nil {
			continue
		}
		utf8Len := utf8.EncodeRune(utf8Bytes, rune(unicodeInt))
		input = append(input[:startIndex], append(utf8Bytes[:utf8Len], input[endIndex:]...)...)
	}
	return input
}

// compareIndices checks that the boundary filter selects exactly the matches
// the \b pattern would have found.
func compareIndices(t *testing.T, data []byte) {
	t.Helper()
	want := legacyCodePointPat.FindAllSubmatchIndex(data, -1)
	got := codePointMatches(bytes.Clone(data))
	if len(want) != len(got) {
		t.Fatalf("input %q: legacy found %d matches %v, filtered found %d %v", data, len(want), want, len(got), got)
	}
	for i := range want {
		for j := range want[i] {
			if want[i][j] != got[i][j] {
				t.Fatalf("input %q: match %d differs: legacy %v filtered %v", data, i, want[i], got[i])
			}
		}
	}
}

// compareDecode checks the full decode output agrees.
func compareDecode(t *testing.T, data []byte) {
	t.Helper()
	want := legacyDecodeCodePoint(bytes.Clone(data))
	got := decodeCodePoint(bytes.Clone(data))
	if !bytes.Equal(want, got) {
		t.Fatalf("input %q: legacy decoded to %q, new decoded to %q", data, want, got)
	}
}

// compareMatched checks the decoder's decode/skip decision agrees.
func compareMatched(t *testing.T, data []byte) {
	t.Helper()
	wantMatched := legacyCodePointPat.Match(data)
	gotMatched := len(codePointMatches(bytes.Clone(data))) > 0
	if wantMatched != gotMatched {
		t.Fatalf("input %q: legacy matched=%v, new matched=%v", data, wantMatched, gotMatched)
	}
}

var codePointSeeds = []string{
	"", "U+0041", "U+0041 ", "U+0041x", "U+0041U+0042", "U+0041 U+0042",
	"AU+0041", "_U+0041", "9U+0041", " U+0041", "\tU+0041", "\nU+0041",
	"AU+0041 U+0042", "U+0041\nU+0042", "U+0041\tU+0042", "U+00",
	"U+ZZZZ", "u+0041", "UU+0041", "U+0041U", "U+0041+", "xU+0041U+0042 U+0043",
	"U+D800", "U+FFFF", "U+0000", "café U+00E9", "\xff\xfeU+0041",
	"U+0041U+0042U+0043", "-U+0041-U+0042-", "U+0041.U+0042", "1U+0041 2U+0042",
}

func TestCodePointBoundaryEquivalence(t *testing.T) {
	for _, s := range codePointSeeds {
		compareIndices(t, []byte(s))
		compareDecode(t, []byte(s))
		compareMatched(t, []byte(s))
	}

	// Alphabet weighted towards everything the pattern and boundary care about.
	alphabet := []byte("UU++0123456789abcdefABCDEFxyz_ \t\n.-\xff")
	rnd := rand.New(rand.NewSource(7))
	for i := 0; i < 300000; i++ {
		b := make([]byte, 1+rnd.Intn(40))
		for j := range b {
			b[j] = alphabet[rnd.Intn(len(alphabet))]
		}
		compareIndices(t, b)
		compareDecode(t, b)
		compareMatched(t, b)
	}
}

// legacyFromChunk is main's whole FromChunk, unanchored and with \b.
func legacyFromChunk(chunk *sources.Chunk) []byte {
	chunkData := bytes.Clone(chunk.Data)
	matched := false
	if longEscapePat.Match(chunkData) {
		matched, chunkData = true, decodeLongEscape(chunkData)
	} else if braceEscapePat.Match(chunkData) {
		matched, chunkData = true, decodeBraceEscape(chunkData)
	} else if perlEscapePat.Match(chunkData) {
		matched, chunkData = true, decodePerlEscape(chunkData)
	} else if htmlEscapePat.Match(chunkData) {
		matched, chunkData = true, decodeHtmlEscape(chunkData)
	} else if percentEscapePat.Match(chunkData) {
		matched, chunkData = true, decodePercentEscape(chunkData)
	} else if escapePat.Match(chunkData) {
		matched, chunkData = true, decodeEscaped(chunkData)
	} else if legacyCodePointPat.Match(chunkData) {
		matched, chunkData = true, legacyDecodeCodePoint(chunkData)
	} else if cssEscapePat.Match(chunkData) {
		matched, chunkData = true, decodeCssEscape(chunkData)
	}
	if !matched {
		return nil
	}
	return chunkData
}

func compareFromChunk(t *testing.T, data []byte) {
	t.Helper()
	want := legacyFromChunk(&sources.Chunk{Data: bytes.Clone(data)})
	got := (&EscapedUnicode{}).FromChunk(&sources.Chunk{Data: bytes.Clone(data)})
	switch {
	case want == nil && got != nil:
		t.Fatalf("new decoded %q to %q, legacy skipped it", data, got.Data)
	case want != nil && got == nil:
		t.Fatalf("new skipped %q, legacy decoded it to %q", data, want)
	case want != nil && !bytes.Equal(want, got.Data):
		t.Fatalf("input %q: legacy %q, new %q", data, want, got.Data)
	}
}

func TestFromChunkEquivalence(t *testing.T) {
	for _, s := range append(codePointSeeds,
		"\\u0041", "\\\\u0041", "\\U0001F600", "\\u{1F600}", "\\x{263A}",
		"&#x41;", "%u0041", "\\41 ", "\\41\\", "plain text", "a+b&c%d\\e",
	) {
		compareFromChunk(t, []byte(s))
	}
	alphabet := []byte(`UU++\\\uUxX{}&#%;0123456789abcdefABCDEF _.-` + "\t\n")
	rnd := rand.New(rand.NewSource(11))
	for i := 0; i < 300000; i++ {
		b := make([]byte, 1+rnd.Intn(48))
		for j := range b {
			b[j] = alphabet[rnd.Intn(len(alphabet))]
		}
		compareFromChunk(t, b)
	}
}

func FuzzCodePointBoundary(f *testing.F) {
	for _, s := range codePointSeeds {
		f.Add([]byte(s))
	}
	f.Add([]byte("\\u0041"))
	f.Add([]byte("&#x41;"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		compareIndices(t, data)
		compareDecode(t, data)
		compareFromChunk(t, data)
	})
}
