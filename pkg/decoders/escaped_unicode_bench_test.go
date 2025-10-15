package decoders

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Benchmark data for testing
var (
	// Original formats
	originalUnicodeData = []byte("\\u0041\\u004b\\u0049\\u0041\\u0055\\u004d\\u0034\\u0047\\u0036\\u004f\\u0036\\u004e\\u0041\\u004b\\u0045\\u0037\\u004c\\u0043\\u0044\\u004a")
	codePointData       = []byte("U+0041 U+004B U+0049 U+0041 U+0055 U+004D U+0034 U+0047 U+0036 U+004F U+0036 U+004E U+0041 U+004B U+0045 U+0037 U+004C U+0043 U+0044 U+004A")

	// New formats
	braceEscapeData   = []byte("\\u{41}\\u{4b}\\u{49}\\u{41}\\u{55}\\u{4d}\\u{34}\\u{47}\\u{36}\\u{4f}\\u{36}\\u{4e}\\u{41}\\u{4b}\\u{45}\\u{37}\\u{4c}\\u{43}\\u{44}\\u{4a}")
	longEscapeData    = []byte("\\U00000041\\U0000004b\\U00000049\\U00000041\\U00000055\\U0000004d\\U00000034\\U00000047\\U00000036\\U0000004f\\U00000036\\U0000004e\\U00000041\\U0000004b\\U00000045\\U00000037\\U0000004c\\U00000043\\U00000044\\U0000004a")
	perlEscapeData    = []byte("\\x{41}\\x{4b}\\x{49}\\x{41}\\x{55}\\x{4d}\\x{34}\\x{47}\\x{36}\\x{4f}\\x{36}\\x{4e}\\x{41}\\x{4b}\\x{45}\\x{37}\\x{4c}\\x{43}\\x{44}\\x{4a}")
	cssEscapeData     = []byte("\\41 \\4b \\49 \\41 \\55 \\4d \\34 \\47 \\36 \\4f \\36 \\4e \\41 \\4b \\45 \\37 \\4c \\43 \\44 \\4a ")
	htmlEscapeData    = []byte("&#x41;&#x4b;&#x49;&#x41;&#x55;&#x4d;&#x34;&#x47;&#x36;&#x4f;&#x36;&#x4e;&#x41;&#x4b;&#x45;&#x37;&#x4c;&#x43;&#x44;&#x4a;")
	percentEscapeData = []byte("%u0041%u004b%u0049%u0041%u0055%u004d%u0034%u0047%u0036%u004f%u0036%u004e%u0041%u004b%u0045%u0037%u004c%u0043%u0044%u004a")
	//hexEscapeData     = []byte("0x41 0x4b 0x49 0x41 0x55 0x4d 0x34 0x47 0x36 0x4f 0x36 0x4e 0x41 0x4b 0x45 0x37 0x4c 0x43 0x44 0x4a ")

	// Mixed content (more realistic scenario)
	mixedContentData = []byte(`
		const config = {
			apiKey: "\\u0041\\u004b\\u0049\\u0041\\u0055\\u004d\\u0034\\u0047\\u0036\\u004f\\u0036\\u004e\\u0041\\u004b\\u0045\\u0037\\u004c\\u0043\\u0044\\u004a",
			secretKey: "\\u{6e}\\u{62}\\u{75}\\u{68}\\u{7a}\\u{4b}\\u{79}\\u{39}\\u{50}\\u{50}\\u{7a}\\u{32}\\u{7a}\\u{47}\\u{33}\\u{47}\\u{54}\\u{4a}\\u{71}\\u{4b}\\u{45}\\u{43}\\u{6e}\\u{71}\\u{4c}\\u{41}\\u{78}\\u{43}\\u{76}\\u{2f}\\u{36}\\u{68}\\u{43}\\u{6a}\\u{6b}\\u{50}\\u{68}\\u{66}\\u{58}\\u{6f}",
			htmlToken: "&#x41;&#x4b;&#x49;&#x41;&#x55;&#x4d;&#x34;&#x47;&#x36;&#x4f;&#x36;&#x4e;&#x41;&#x4b;&#x45;&#x37;&#x4c;&#x43;&#x44;&#x4a;",
			normalText: "This is normal text that should not be processed"
		}
	`)

	// Large data for stress testing
	largeData = func() []byte {
		data := make([]byte, 0, 10000)
		for i := 0; i < 100; i++ {
			data = append(data, originalUnicodeData...)
			data = append(data, braceEscapeData...)
			data = append(data, longEscapeData...)
			data = append(data, htmlEscapeData...)
			data = append(data, []byte(" normal text ")...)
		}
		return data
	}()

	// No Unicode data (worst case for performance)
	noUnicodeData = []byte(`
		This is a large block of text with no Unicode escape sequences.
		It contains various programming constructs like:
		- Variable declarations: var x = 123;
		- Function calls: doSomething(param1, param2);
		- Comments: /* this is a comment */
		- Strings: "hello world"
		- Numbers: 42, 3.14159, 0xFF
		- But no Unicode escapes that would trigger our decoders.
		This simulates the common case where files don't contain Unicode escapes.
	`)
)

// Benchmark individual decoder functions
func BenchmarkDecodeOriginalEscape(b *testing.B) {
	for b.Loop() {
		_ = decodeEscaped(originalUnicodeData)
	}
}

func BenchmarkDecodeCodePoint(b *testing.B) {
	for b.Loop() {
		_ = decodeCodePoint(codePointData)
	}
}

func BenchmarkDecodeBraceEscape(b *testing.B) {
	for b.Loop() {
		_ = decodeBraceEscape(braceEscapeData)
	}
}

func BenchmarkDecodeLongEscape(b *testing.B) {
	for b.Loop() {
		_ = decodeLongEscape(longEscapeData)
	}
}

func BenchmarkDecodePerlEscape(b *testing.B) {
	for b.Loop() {
		_ = decodePerlEscape(perlEscapeData)
	}
}

func BenchmarkDecodeCssEscape(b *testing.B) {
	for b.Loop() {
		_ = decodeCssEscape(cssEscapeData)
	}
}

func BenchmarkDecodeHtmlEscape(b *testing.B) {
	for b.Loop() {
		_ = decodeHtmlEscape(htmlEscapeData)
	}
}

func BenchmarkDecodePercentEscape(b *testing.B) {
	for b.Loop() {
		_ = decodePercentEscape(percentEscapeData)
	}
}

// func BenchmarkDecodeHexEscape(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		_ = decodeHexEscape(hexEscapeData)
// 	}
// }

// Benchmark the full FromChunk method with different data types
func BenchmarkFromChunk_OriginalFormat(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: originalUnicodeData}

	for b.Loop() {
		_ = decoder.FromChunk(chunk)
	}
}

func BenchmarkFromChunk_BraceFormat(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: braceEscapeData}

	for b.Loop() {
		_ = decoder.FromChunk(chunk)
	}
}

func BenchmarkFromChunk_LongFormat(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: longEscapeData}

	for b.Loop() {
		_ = decoder.FromChunk(chunk)
	}
}

func BenchmarkFromChunk_HtmlFormat(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: htmlEscapeData}

	for b.Loop() {
		_ = decoder.FromChunk(chunk)
	}
}

func BenchmarkFromChunk_MixedContent(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: mixedContentData}

	for b.Loop() {
		_ = decoder.FromChunk(chunk)
	}
}

func BenchmarkFromChunk_NoUnicode(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: noUnicodeData}

	for b.Loop() {
		_ = decoder.FromChunk(chunk)
	}
}

func BenchmarkFromChunk_LargeData(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: largeData}

	for b.Loop() {
		_ = decoder.FromChunk(chunk)
	}
}

// Benchmark regex matching performance (most expensive operation)
func BenchmarkRegexMatching_AllPatterns(b *testing.B) {
	testData := mixedContentData

	for b.Loop() {
		// Simulate the pattern matching in FromChunk
		_ = longEscapePat.Match(testData)
		_ = braceEscapePat.Match(testData)
		_ = perlEscapePat.Match(testData)
		_ = htmlEscapePat.Match(testData)
		_ = percentEscapePat.Match(testData)
		_ = escapePat.Match(testData)
		_ = codePointPat.Match(testData)
		_ = cssEscapePat.Match(testData)
		//_ = hexEscapePat.Match(testData)
	}
}

func BenchmarkRegexMatching_NoMatch(b *testing.B) {
	testData := noUnicodeData

	for b.Loop() {
		// Simulate the pattern matching in FromChunk on data with no matches
		_ = longEscapePat.Match(testData)
		_ = braceEscapePat.Match(testData)
		_ = perlEscapePat.Match(testData)
		_ = htmlEscapePat.Match(testData)
		_ = percentEscapePat.Match(testData)
		_ = escapePat.Match(testData)
		_ = codePointPat.Match(testData)
		_ = cssEscapePat.Match(testData)
		//_ = hexEscapePat.Match(testData)
	}
}

// Memory allocation benchmarks
func BenchmarkFromChunk_MemoryAllocation(b *testing.B) {
	decoder := &EscapedUnicode{}
	chunk := &sources.Chunk{Data: mixedContentData}

	b.ReportAllocs()
	for b.Loop() {
		result := decoder.FromChunk(chunk)
		if result != nil {
			// Prevent compiler optimization
			_ = result.Data
		}
	}
}
