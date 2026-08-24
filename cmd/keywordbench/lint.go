package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
)

// renderStaticLint is the corpus-free check: it runs in a second and catches the
// structural problems worth fixing before anyone spends hours scanning.
func renderStaticLint(w io.Writer, sc *scanner, dict string) {
	rule(w, "=")
	fmt.Fprintf(w, "  %s  --  STATIC KEYWORD LINT\n", strings.ToUpper(displayName(sc.target)))
	rule(w, "=")
	fmt.Fprintf(w, "\n  keywords: %s\n\n", quoteAll(sc.target.Keywords()))

	findings := lintKeywords(sc, sc.target.Keywords(), dict)
	if len(findings) == 0 {
		fmt.Fprintf(w, "  No structural problems found.\n")
	}
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", wrap(f, 72, "    "))
	}
	fmt.Fprintf(w, "\n  No corpus was scanned, so this says nothing about how often these\n")
	fmt.Fprintf(w, "  keywords actually fire. For that:\n\n")
	fmt.Fprintf(w, "    make keywordbench CORPUS=<file> TARGET=%s\n", displayName(sc.target))
}

// lintKeywords catches the structural problems that are visible without a corpus,
// so a new detector can be sanity-checked before anyone spends hours scanning.
func lintKeywords(sc *scanner, keywords []string, dictPath string) []string {
	var out []string
	median := medianKeywordLen(sc)
	words := loadDict(dictPath)

	seen := make(map[string]struct{}, len(keywords))
	for _, kw := range keywords {
		lower := strings.ToLower(strings.TrimSpace(kw))

		if kw != strings.TrimSpace(kw) {
			out = append(out, fmt.Sprintf("%q has leading or trailing whitespace, which the prefilter matches literally", kw))
		}
		if _, dup := seen[lower]; dup {
			out = append(out, fmt.Sprintf("%q is listed twice; keywords are a union, so the duplicate does nothing", kw))
		}
		seen[lower] = struct{}{}

		if len(lower) < 5 {
			out = append(out, fmt.Sprintf("%q is %d chars; the median keyword is %d. Short keywords match inside unrelated identifiers",
				kw, len(lower), median))
		}
		if _, ok := words[lower]; ok {
			out = append(out, fmt.Sprintf("%q is an English dictionary word, so it will fire on prose as well as code", kw))
		}
		if len(lower) <= 5 && (strings.HasSuffix(lower, "_") || strings.HasSuffix(lower, "-")) {
			out = append(out, fmt.Sprintf("%q is a short fragment ending in a separator; the prefilter matches "+
				"substrings with no word boundary, so it fires inside any identifier that contains it", kw))
		}
		if owners := sc.kwOwners[lower]; len(owners) > 1 {
			out = append(out, fmt.Sprintf("%q is shared with %d other detector(s): %s. Every hit wakes all of them",
				kw, len(owners)-1, strings.Join(uniqueOwners(owners), ", ")))
		}
		if hosts := containingKeywords(sc, lower); len(hosts) > 0 {
			out = append(out, fmt.Sprintf("%q is a substring of %d other keyword(s) (%s), so it fires wherever they do, and more",
				kw, len(hosts), strings.Join(truncate(hosts, 4), ", ")))
		}
	}
	return out
}

func uniqueOwners(owners []string) []string {
	uniq := slices.Clone(owners)
	sort.Strings(uniq)
	return truncate(slices.Compact(uniq), 5)
}

// containingKeywords finds other detectors' keywords that contain kw, which means
// kw is a generic fragment rather than a vendor-specific marker.
func containingKeywords(sc *scanner, kw string) []string {
	var hosts []string
	for other := range sc.kwOwners {
		if other != kw && strings.Contains(other, kw) {
			hosts = append(hosts, strconvQuote(other))
		}
	}
	sort.Strings(hosts)
	return hosts
}

func truncate(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return append(slices.Clone(ss[:n]), fmt.Sprintf("+%d more", len(ss)-n))
}

func strconvQuote(s string) string { return `"` + s + `"` }

func medianKeywordLen(sc *scanner) int {
	lens := make([]int, 0, len(sc.kwOwners))
	for kw := range sc.kwOwners {
		lens = append(lens, len(kw))
	}
	if len(lens) == 0 {
		return 0
	}
	slices.Sort(lens)
	return lens[len(lens)/2]
}

var dictOnce struct {
	sync.Once
	words map[string]struct{}
}

// loadDict is best-effort: no word list just means the dictionary check is skipped.
func loadDict(path string) map[string]struct{} {
	dictOnce.Do(func() {
		dictOnce.words = make(map[string]struct{})
		fh, err := os.Open(path)
		if err != nil {
			return
		}
		defer fh.Close()
		s := bufio.NewScanner(fh)
		for s.Scan() {
			if w := strings.ToLower(strings.TrimSpace(s.Text())); len(w) > 2 {
				dictOnce.words[w] = struct{}{}
			}
		}
	})
	return dictOnce.words
}
