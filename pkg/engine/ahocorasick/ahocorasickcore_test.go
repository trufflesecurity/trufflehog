package ahocorasick

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"

	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const TestDetectorType = -1

type testDetectorV1 struct {
}

func (testDetectorV1) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV1) Keywords() []string { return []string{"a", "b"} }

func (testDetectorV1) Type() detector_typepb.DetectorType {
	return TestDetectorType
}

func (testDetectorV1) Version() int { return 1 }

func (testDetectorV1) Description() string { return "" }

type testDetectorV2 struct {
}

func (testDetectorV2) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV2) Keywords() []string {
	return []string{"a"}
}

func (testDetectorV2) Type() detector_typepb.DetectorType {
	return TestDetectorType
}

func (testDetectorV2) Version() int { return 2 }

func (testDetectorV2) Description() string { return "" }

type testDetectorV3 struct {
}

func (testDetectorV3) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV3) Keywords() []string {
	return []string{"truffle"}
}

func (testDetectorV3) Type() detector_typepb.DetectorType {
	return TestDetectorType
}

func (testDetectorV3) Version() int { return 1 }

func (testDetectorV3) Description() string { return "" }

var _ detectors.Detector = (*testDetectorV4)(nil)
var _ detectors.MultiPartCredentialProvider = (*testDetectorV4)(nil)
var _ detectors.StartOffsetProvider = (*testDetectorV4)(nil)

type testDetectorV4 struct{}

func (testDetectorV4) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV4) Keywords() []string { return []string{"password"} }

func (testDetectorV4) Type() detector_typepb.DetectorType { return TestDetectorType }

func (testDetectorV4) Version() int { return 1 }

func (testDetectorV4) Description() string { return "" }

func (testDetectorV4) MaxCredentialSpan() int64 { return 15 }

func (testDetectorV4) StartOffset() int64 { return 5 }

var _ detectors.Detector = (*testDetectorV5)(nil)
var _ detectors.MaxSecretSizeProvider = (*testDetectorV5)(nil)
var _ detectors.StartOffsetProvider = (*testDetectorV5)(nil)

type testDetectorV5 struct{}

func (testDetectorV5) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV5) Keywords() []string { return []string{"password"} }

func (testDetectorV5) Type() detector_typepb.DetectorType { return TestDetectorType }

func (testDetectorV5) Version() int { return 1 }

func (testDetectorV5) Description() string { return "" }

func (testDetectorV5) MaxSecretSize() int64 { return 10 }

func (testDetectorV5) StartOffset() int64 { return 3 }

var _ detectors.Detector = (*testDetectorV6)(nil)
var _ detectors.Detector = (*testDetectorV6)(nil)
var _ detectors.StartOffsetProvider = (*testDetectorV6)(nil)

type testDetectorV6 struct{}

func (testDetectorV6) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return make([]detectors.Result, 0), nil
}

func (testDetectorV6) Keywords() []string { return []string{"password"} }

func (testDetectorV6) Type() detector_typepb.DetectorType { return TestDetectorType }

func (testDetectorV6) Version() int { return 1 }

func (testDetectorV6) Description() string { return "" }

func (testDetectorV6) StartOffset() int64 { return 1 }

var _ detectors.Detector = (*testDetectorV1)(nil)
var _ detectors.Detector = (*testDetectorV2)(nil)
var _ detectors.Versioner = (*testDetectorV1)(nil)
var _ detectors.Versioner = (*testDetectorV2)(nil)
var _ detectors.Versioner = (*testDetectorV3)(nil)

func TestAhoCorasickCore_MultipleCustomDetectorsMatchable(t *testing.T) {
	customDetector1, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 1",
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	customDetector2, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 2",
		Keywords: []string{"a"},
		Regex:    map[string]string{"": ""},
	})
	assert.Nil(t, err)

	allDetectors := []detectors.Detector{customDetector1, customDetector2}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_MultipleDetectorVersionsMatchable(t *testing.T) {
	v1 := testDetectorV1{}
	v2 := testDetectorV2{}
	allDetectors := []detectors.Detector{v1, v2}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestAhoCorasickCore_NoDuplicateDetectorsMatched(t *testing.T) {
	d := testDetectorV1{}
	allDetectors := []detectors.Detector{d}

	ac := NewAhoCorasickCore(allDetectors)

	dts := ac.FindDetectorMatches([]byte("a a b b"))
	matchingDetectors := make([]detectors.Detector, 0, 2)
	for _, d := range dts {
		matchingDetectors = append(matchingDetectors, d.Detector)
	}
	assert.ElementsMatch(t, allDetectors, matchingDetectors)
}

func TestFindDetectorMatches(t *testing.T) {
	testCases := []struct {
		name           string
		opts           []CoreOption
		detectors      []detectors.Detector
		sampleData     string
		expectedResult map[DetectorKey][][]int64
	}{

		{
			name: "single matchSpan",
			detectors: []detectors.Detector{
				testDetectorV3{},
			},
			sampleData: "This is a sample data containing keyword truffle",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV3{}): {{0, 48}},
			},
		},
		{
			name: "Multiple matches overlapping",
			detectors: []detectors.Detector{
				testDetectorV1{},
			},
			sampleData: "This is a sample data containing keyword a",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV1{}): {{0, 42}},
			},
		},
		{
			name: "Multiple matches",
			detectors: []detectors.Detector{
				testDetectorV2{},
			},
			sampleData: `This is the first occurrence of the letter a.
                 Lorem ipsum dolor sit met, consectetur dipiscing elit. Sed uctor,
                 mgn bibendum bibendum, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. Donec
                 sed ugue. Sed euismod, ugue sit met liqum lcini,
                 ugue ugue tincidunt ugue, eget ultricies ugue ugue id
                 ugue. Meens liquet libero c libero molestie, nec
                 mlesud ugue ugue eget. Donec sed ugue. Sed euismod,
                 ugue sit met liqum lcini, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. This is the second occurrence of the letter a.`,
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV2{}): {{0, 856}},
			},
		},
		{
			name: "single matchSpan; entireSpanChunkCalculator",
			opts: []CoreOption{WithSpanCalculator(&EntireChunkSpanCalculator{})},
			detectors: []detectors.Detector{
				testDetectorV3{},
			},
			sampleData: "This is a sample data containing keyword truffle",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV3{}): {{0, 48}},
			},
		},
		{
			name: "Multiple matches overlapping; entireSpanChunkCalculator",
			opts: []CoreOption{WithSpanCalculator(&EntireChunkSpanCalculator{})},
			detectors: []detectors.Detector{
				testDetectorV1{},
			},
			sampleData: "This is a sample data containing keyword a",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV1{}): {{0, 42}},
			},
		},
		{
			name: "Multiple matches; entireSpanChunkCalculator",
			opts: []CoreOption{WithSpanCalculator(&EntireChunkSpanCalculator{})},
			detectors: []detectors.Detector{
				testDetectorV2{},
			},
			sampleData: `This is the first occurrence of the letter a.
                 Lorem ipsum dolor sit met, consectetur dipiscing elit. Sed uctor,
                 mgn bibendum bibendum, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. Donec
                 sed ugue. Sed euismod, ugue sit met liqum lcini,
                 ugue ugue tincidunt ugue, eget ultricies ugue ugue id
                 ugue. Meens liquet libero c libero molestie, nec
                 mlesud ugue ugue eget. Donec sed ugue. Sed euismod,
                 ugue sit met liqum lcini, ugue ugue tincidunt ugue,
                 eget ultricies ugue ugue id ugue. Meens liquet libero
                 c libero molestie, nec mlesud ugue ugue eget. This is the second occurrence of the letter a.`,
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV2{}): {{0, 856}},
			},
		},
		{
			name: "keyword in the middle of the credential; MultiPartCredentialProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV4{},
			},
			sampleData: "This is a password in the middle of some data",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV4{}): {{5, 25}},
			},
		},
		{
			name: "keyword at the end of the credential; MultiPartCredentialProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV4{},
			},
			sampleData: "This data ends with a password",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV4{}): {{17, 30}},
			},
		},
		{
			name: "keyword near the start of the data; MultiPartCredentialProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV4{},
			},
			sampleData: "a password at the start",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV4{}): {{0, 17}},
			},
		},
		{
			name: "keyword in the middle of the credential; MaxSecretSizeProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV5{},
			},
			sampleData: "This is a password in the middle of some data",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV5{}): {{7, 20}},
			},
		},
		{
			name: "keyword at the end of the credential; MaxSecretSizeProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV5{},
			},
			sampleData: "This data ends with a password",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV5{}): {{19, 30}},
			},
		},
		{
			name: "keyword near the start of the data; MaxSecretSizeProvider, StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV5{},
			},
			sampleData: "a password at the start",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV5{}): {{0, 12}},
			},
		},
		{
			name: "keyword in the middle of the credential; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "This is a password in the middle of some data",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{9, 45}},
			},
		},
		{
			name: "keyword at the end of the credential; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "This data ends with a password",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{21, 30}},
			},
		},
		{
			name: "keyword near the start of the data; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "a password at the start",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{1, 23}},
			},
		},
		{
			name: "multiple keyword in the middle of the credential; StartOffsetProvider",
			detectors: []detectors.Detector{
				testDetectorV6{},
			},
			sampleData: "This is a password in the middle of some data, and another password at the end!",
			expectedResult: map[DetectorKey][][]int64{
				CreateDetectorKey(testDetectorV6{}): {{9, 79}},
			},
		},
		{
			name: "No matches",
			detectors: []detectors.Detector{
				testDetectorV1{},
				testDetectorV2{},
			},
			sampleData:     "xxy yzz lnnope",
			expectedResult: map[DetectorKey][][]int64{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ac := NewAhoCorasickCore(tc.detectors, tc.opts...)
			detectorMatches := ac.FindDetectorMatches([]byte(tc.sampleData))

			// Verify that all matching detectors and their matches are returned.
			for _, detectorMatch := range detectorMatches {
				assert.Contains(t, tc.expectedResult, detectorMatch.Key, "Expected detector key to be present")

				expectedMatches := tc.expectedResult[detectorMatch.Key]
				actualMatches := make([][]int64, len(detectorMatch.matchSpans))
				for i, match := range detectorMatch.matchSpans {
					actualMatches[i] = []int64{match.startOffset, match.endOffset}
				}

				assert.ElementsMatch(t, expectedMatches, actualMatches, "Expected matches to be returned for the detector")
			}

			// Verify that all expected matches are returned for each detector.
			for key, expectedMatches := range tc.expectedResult {
				var actualMatches [][]int64
				for _, detectorMatch := range detectorMatches {
					if detectorMatch.Key == key {
						for _, match := range detectorMatch.matchSpans {
							actualMatches = append(actualMatches, []int64{match.startOffset, match.endOffset})
						}
					}
				}
				assert.ElementsMatch(t, expectedMatches, actualMatches, "Expected all matches to be returned for the detector")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Case folding
//
// FindDetectorMatches searches a lowercased copy of the chunk, then cuts spans
// out of the original. That only works while the copy is the same length as
// the original, which is why only A-Z is lowered.
// ---------------------------------------------------------------------------

// keywordDetector matches on one caller-chosen keyword.
type keywordDetector struct{ keyword string }

func (keywordDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return nil, nil
}
func (k keywordDetector) Keywords() []string { return []string{k.keyword} }
func (keywordDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Generic
}
func (keywordDetector) Description() string { return "" }

func TestAppendASCIILower(t *testing.T) {
	// Must agree with the standard library across the whole ASCII range.
	var ascii []byte
	for c := range 128 {
		ascii = append(ascii, byte(c))
	}
	assert.Equal(t, bytes.ToLower(ascii), appendASCIILower(nil, ascii))

	// Must never change length, unlike bytes.ToLower. Each of these shrinks
	// when lowercased the normal way, which is what would move the spans.
	for _, s := range []string{"İ", "ẞ", "İİİ", "prefix ẞ suffix"} {
		assert.Len(t, appendASCIILower(nil, []byte(s)), len(s), "input %q", s)
		assert.NotEqual(t, len(s), len(bytes.ToLower([]byte(s))),
			"bytes.ToLower(%q) no longer changes length, so this case proves nothing", s)
	}
}

func TestFindDetectorMatchesIsCaseInsensitive(t *testing.T) {
	core := NewAhoCorasickCore([]detectors.Detector{keywordDetector{"sendgrid"}})
	for _, chunk := range []string{"sendgrid", "SENDGRID", "SendGrid"} {
		assert.Len(t, core.FindDetectorMatches([]byte(chunk)), 1, "chunk %q", chunk)
	}
}

// Multi-byte characters before a keyword must not move the span off it.
func TestFindDetectorMatchesSpansSurviveMultibyte(t *testing.T) {
	const keyword = "sekrit"
	core := NewAhoCorasickCore([]detectors.Detector{keywordDetector{keyword}})

	// The run of "İ" is longer than the window the span calculator adds around
	// a hit, otherwise the window would cover the keyword regardless and a
	// wrong position would go unnoticed.
	chunk := []byte(strings.Repeat("İ", 700) + " padding " + keyword + " trailing")

	matches := core.FindDetectorMatches(chunk)
	assert.Len(t, matches, 1)
	for _, m := range matches[0].matches {
		assert.Contains(t, string(m), keyword)
	}
}

// Whatever surrounds a keyword, the span cut for it must stay inside the chunk
// and must still cover the keyword that produced it.
//
// Positions come from the lowercased copy while the bytes are cut from the
// original, so this holds only while folding preserves length. The generator
// leans on characters where that is easy to get wrong: "İ" and "ẞ" both shrink
// under full Unicode lowercasing, and the raw tail is arbitrary bytes that need
// not be valid UTF-8.
func TestFindDetectorMatchesSpanProperties(t *testing.T) {
	const keyword = "token"
	core := NewAhoCorasickCore([]detectors.Detector{keywordDetector{keyword}})

	// Padding is built from long runs of one character rather than a random
	// mix, so it reliably grows past the window the span calculator adds around
	// a hit. A drifting position is only observable outside that window.
	interesting := []rune{'a', 'Z', ' ', 'é', 'İ', 'ẞ', 'Κ', '密'}
	padding := rapid.Custom(func(t *rapid.T) string {
		var sb strings.Builder
		for range rapid.IntRange(0, 3).Draw(t, "runs") {
			sb.WriteString(strings.Repeat(
				string(rapid.SampledFrom(interesting).Draw(t, "char")),
				rapid.IntRange(0, 600).Draw(t, "runLength"),
			))
		}
		return sb.String()
	})

	rapid.Check(t, func(t *rapid.T) {
		chunk := []byte(padding.Draw(t, "prefix") + keyword + padding.Draw(t, "suffix"))
		chunk = append(chunk, rapid.SliceOf(rapid.Byte()).Draw(t, "tail")...)

		matches := core.FindDetectorMatches(chunk)
		if len(matches) != 1 {
			t.Fatalf("keyword present but got %d detector matches", len(matches))
		}

		spans := matches[0].matchSpans
		if len(spans) == 0 {
			t.Fatal("detector matched but no spans were produced")
		}
		for _, span := range spans {
			if span.startOffset < 0 || span.startOffset > span.endOffset ||
				span.endOffset > int64(len(chunk)) {
				t.Fatalf("span [%d,%d) outside chunk of %d bytes",
					span.startOffset, span.endOffset, len(chunk))
			}
			// Every span comes from at least one hit, so slicing the original
			// chunk with it must give back text containing the keyword.
			text := string(chunk[span.startOffset:span.endOffset])
			if !strings.Contains(strings.ToLower(text), keyword) {
				t.Fatalf("span [%d,%d) does not cover the keyword",
					span.startOffset, span.endOffset)
			}
		}
	})
}

// A buffer coming back from the pool still holds the previous chunk's bytes,
// so a later, shorter chunk must not be able to see them.
func TestLowerBufPoolReuseIsClean(t *testing.T) {
	core := NewAhoCorasickCore([]detectors.Detector{keywordDetector{"token"}})

	long := []byte(strings.Repeat("x", 4096) + "token" + strings.Repeat("y", 4096))
	assert.Len(t, core.FindDetectorMatches(long), 1)

	short := []byte("token")
	matches := core.FindDetectorMatches(short)
	assert.Len(t, matches, 1)
	for _, m := range matches[0].matchSpans {
		assert.LessOrEqual(t, m.endOffset, int64(len(short)),
			"leftover bytes from the previous chunk leaked through the pool")
	}
}

// The pool is shared by every scanner worker.
func TestFindDetectorMatchesConcurrent(t *testing.T) {
	core := NewAhoCorasickCore([]detectors.Detector{keywordDetector{"token"}})
	chunks := [][]byte{
		[]byte("token here"),
		[]byte(strings.Repeat("padding ", 500) + "token"),
		[]byte("İİİ token"),
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				for _, c := range chunks {
					for _, m := range core.FindDetectorMatches(c) {
						for _, span := range m.matchSpans {
							if span.endOffset > int64(len(c)) {
								panic("span escaped the chunk")
							}
						}
					}
				}
			}
		})
	}
	wg.Wait()
}

// Lowering only A-Z is safe only while every keyword is ASCII, since a
// non-ASCII byte then cannot be part of any match.
func TestAllDefaultKeywordsAreASCII(t *testing.T) {
	for _, d := range defaults.DefaultDetectors() {
		for _, kw := range d.Keywords() {
			for i := range len(kw) {
				assert.Less(t, kw[i], byte(utf8.RuneSelf),
					"%v keyword %q is not ASCII", d.Type(), kw)
			}
		}
	}
}

// FuzzAppendASCIILower checks the two properties the spans rely on: the output
// is always the same length as the input, and only A-Z changes.
func FuzzAppendASCIILower(f *testing.F) {
	for _, seed := range []string{"", "token", "TOKEN", "İ", "ẞ", "\x00\xff", "MiXeD 123"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		got := appendASCIILower(nil, src)
		if len(got) != len(src) {
			t.Fatalf("length changed: %d -> %d", len(src), len(got))
		}
		for i, c := range src {
			want := c
			if c >= 'A' && c <= 'Z' {
				want = c + ('a' - 'A')
			}
			if got[i] != want {
				t.Fatalf("byte %d: %q became %q, want %q", i, c, got[i], want)
			}
		}
	})
}

// Keywords are folded the same way chunks are, so matching ignores ASCII case.
// A cased non-ASCII letter is left as written on both sides, so it matches only
// text spelling that letter the same way. Built-in keywords are all ASCII, so
// this only ever affects a custom detector.
func TestKeywordFoldingMatchesChunkFolding(t *testing.T) {
	for _, tc := range []struct {
		keyword string
		matches []string
		misses  []string
	}{
		// ASCII folds fully, so every spelling matches.
		{"TOKEN", []string{"token", "TOKEN", "Token"}, nil},
		// The ASCII letters still fold; the "É" must be written as it was.
		{"CAFÉ", []string{"CAFÉ", "cafÉ"}, []string{"café", "Café"}},
		// Scripts without letter case are unaffected.
		{"密钥", []string{"密钥"}, nil},
	} {
		core := NewAhoCorasickCore([]detectors.Detector{keywordDetector{tc.keyword}})
		for _, chunk := range tc.matches {
			assert.Len(t, core.FindDetectorMatches([]byte(chunk)), 1,
				"keyword %q should match chunk %q", tc.keyword, chunk)
		}
		for _, chunk := range tc.misses {
			assert.Empty(t, core.FindDetectorMatches([]byte(chunk)),
				"keyword %q should not match chunk %q", tc.keyword, chunk)
		}
	}
}

// A keyword is registered under one spelling, so a single occurrence reports a
// single match rather than one per spelling.
func TestKeywordRegisteredOnce(t *testing.T) {
	core := NewAhoCorasickCore([]detectors.Detector{keywordDetector{"token"}})
	assert.Len(t, core.keywordsToDetectors["token"], 1)

	matches := core.FindDetectorMatches([]byte("token"))
	assert.Len(t, matches, 1)
	assert.Len(t, matches[0].matchSpans, 1, "keyword counted twice")
}

// BenchmarkLowerBuf shows what the pool is for: borrowing a buffer costs no
// allocation, while building a fresh lowercased copy allocates one per chunk.
func BenchmarkLowerBuf(b *testing.B) {
	data := []byte(strings.Repeat("The Quick Brown Fox Jumps Over A Sleeping Dog\n", 200))

	b.Run("pooled", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(data)))
		for range b.N {
			buf := getLowerBuf(len(data))
			buf.b = appendASCIILower(buf.b[:0], data)
			putLowerBuf(buf)
		}
	})
	b.Run("unpooled", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(data)))
		for range b.N {
			_ = appendASCIILower(make([]byte, 0, len(data)), data)
		}
	})
}
