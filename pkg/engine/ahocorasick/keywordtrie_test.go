package ahocorasick

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	bobu "github.com/BobuSumisu/aho-corasick"
	"pgregory.net/rapid"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// keywordTrie replaced github.com/BobuSumisu/aho-corasick, which searched a
// lowercased copy of each chunk. These tests check that keywordTrie, reading
// the chunk as it is, reports exactly the same matches in the same order.

type keywordHit struct {
	start   int64
	keyword string
}

func bobuHits(keywords []string, data []byte) []keywordHit {
	var hits []keywordHit
	for _, m := range bobu.NewTrieBuilder().AddStrings(keywords).Build().Match(data) {
		hits = append(hits, keywordHit{m.Pos(), m.MatchString()})
	}
	return hits
}

func trieHits(keywords []string, data []byte) []keywordHit {
	var hits []keywordHit
	newKeywordTrie(keywords).walk(data, func(start int64, keyword string) {
		hits = append(hits, keywordHit{start, keyword})
	})
	return hits
}

func assertSameHits(t interface {
	Helper()
	Fatalf(string, ...any)
}, keywords []string, data []byte) {
	t.Helper()
	folded := make([]string, len(keywords))
	for i, kw := range keywords {
		folded[i] = string(appendASCIILower(nil, []byte(kw)))
	}
	want := bobuHits(folded, appendASCIILower(nil, data))
	got := trieHits(folded, data)
	if fmt.Sprint(want) != fmt.Sprint(got) {
		t.Fatalf("keywords %q, data %q:\n got: %v\nwant: %v", keywords, data, got, want)
	}
}

func TestKeywordTrie_MatchesBobu(t *testing.T) {
	cases := []struct {
		keywords []string
		data     string
	}{
		{[]string{"he", "she", "his", "hers"}, "ushers"},
		{[]string{"token", "TOKEN"}, "Token TOKEN token"},
		{[]string{"a", "ab", "abc", "bc", "c"}, "abcabc"},
		{[]string{"aaa", "aa", "a"}, "aaaaa"},
		{[]string{"dup", "dup", "up"}, "dupdup"},
		{[]string{"", "x"}, "xx"},
		{[]string{"caf\xc3\xa9", "\xff"}, "caf\xc3\xa9 \xff"},
		{[]string{"key"}, ""},
		{nil, "anything"},
	}
	for _, c := range cases {
		assertSameHits(t, c.keywords, []byte(c.data))
	}
}

func TestKeywordTrie_MatchesBobu_Random(t *testing.T) {
	alphabet := rapid.SampledFrom([]byte("abcABC[`@-_.\x00\xc3\xff"))
	word := rapid.Custom(func(t *rapid.T) string {
		return string(rapid.SliceOfN(alphabet, 0, 6).Draw(t, "word"))
	})
	rapid.Check(t, func(t *rapid.T) {
		keywords := rapid.SliceOfN(word, 0, 20).Draw(t, "keywords")
		data := rapid.SliceOfN(alphabet, 0, 200).Draw(t, "data")
		assertSameHits(t, keywords, data)
	})
}

func TestKeywordTrie_MatchesBobu_EveryByte(t *testing.T) {
	var keywords []string
	var data []byte
	for b := range 256 {
		keywords = append(keywords, string([]byte{byte(b), byte(b)}))
		data = append(data, byte(b), byte(b))
	}
	assertSameHits(t, keywords, data)
}

func TestKeywordTrie_MatchesBobu_DefaultKeywordsOnSource(t *testing.T) {
	var keywords []string
	for _, d := range defaults.DefaultDetectors() {
		keywords = append(keywords, d.Keywords()...)
	}
	for _, chunk := range sourceChunks(t) {
		assertSameHits(t, keywords, chunk)
	}
}

func sourceChunks(tb testing.TB) [][]byte {
	tb.Helper()
	files, err := filepath.Glob("../../*/*.go")
	if err != nil {
		tb.Fatal(err)
	}
	var chunks [][]byte
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			tb.Fatal(err)
		}
		for i := 0; i < len(data); i += 10 * 1024 {
			chunks = append(chunks, data[i:min(i+10*1024, len(data))])
		}
	}
	return chunks
}

func BenchmarkFindDetectorMatches(b *testing.B) {
	core := NewAhoCorasickCore(defaults.DefaultDetectors())
	chunks := sourceChunks(b)
	size := 0
	for _, c := range chunks {
		size += len(c)
	}
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for b.Loop() {
		for _, c := range chunks {
			core.FindDetectorMatches(c)
		}
	}
}
