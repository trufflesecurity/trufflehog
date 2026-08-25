package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// renderStaticLint is the corpus-free check: it runs in a second and catches the
// structural problems worth fixing before anyone spends hours scanning.
func renderStaticLint(w io.Writer, sc *scanner, dict string) {
	rule(w, "=")
	fmt.Fprintf(w, "  %s  --  QUICK KEYWORD CHECK\n", strings.ToUpper(displayName(sc.target)))
	rule(w, "=")
	fmt.Fprintf(w, "\n  keywords: %s\n\n", quoteAll(sc.target.Keywords()))

	findings := lintKeywords(sc, sc.target.Keywords(), dict)
	if len(findings) == 0 {
		fmt.Fprintf(w, "  Nothing obviously wrong with these keywords.\n")
	}
	for _, f := range findings {
		fmt.Fprintf(w, "  - %s\n", wrap(f, 72, "    "))
	}
	fmt.Fprintf(w, "\n  No data was scanned, so this says nothing about how often these keywords\n")
	fmt.Fprintf(w, "  actually match. To measure that:\n\n")
	fmt.Fprintf(w, "    make keywordbench CORPUS=<file> TARGET=%s\n", displayName(sc.target))
}

// lintKeywords catches the problems that are visible without scanning anything, so
// a new detector can be sanity-checked before anyone spends hours on a corpus.
// Findings that apply to several keywords are reported once, listing them together.
func lintKeywords(sc *scanner, keywords []string, dictPath string) []string {
	median := medianKeywordLen(sc)
	words := loadDict(dictPath)

	// note collects keywords per problem, in first-seen order. Problems carry a
	// plural form because the grouped line reads "a, b -- <problem>".
	type problem struct{ one, many string }
	var order []problem
	byProblem := make(map[problem][]string)
	note := func(p problem, kw string) {
		if _, seen := byProblem[p]; !seen {
			order = append(order, p)
		}
		byProblem[p] = append(byProblem[p], strconv.Quote(kw))
	}

	var out []string
	seen := make(map[string]struct{}, len(keywords))
	for _, kw := range keywords {
		lower := strings.ToLower(strings.TrimSpace(kw))

		if kw != strings.TrimSpace(kw) {
			note(problem{one: "has a space at the start or end, which is matched literally and is probably a mistake",
				many: "have a space at the start or end, which is matched literally and is probably a mistake"}, kw)
		}
		if _, dup := seen[lower]; dup {
			note(problem{one: "is listed twice. Any one keyword is enough to start the detector, so the copy does nothing",
				many: "are listed more than once. Any one keyword is enough to start the detector, so the copies do nothing"}, kw)
		}
		seen[lower] = struct{}{}

		if len(lower) < 5 {
			note(problem{
				one:  fmt.Sprintf("is under 5 characters long. Half of all detector keywords are %d or more, and short keywords turn up inside unrelated words", median),
				many: fmt.Sprintf("are under 5 characters long. Half of all detector keywords are %d or more, and short keywords turn up inside unrelated words", median),
			}, kw)
		}
		if _, ok := words[lower]; ok {
			note(problem{one: "is an ordinary English word, so it will match normal writing as well as code",
				many: "are ordinary English words, so they will match normal writing as well as code"}, kw)
		}
		if len(lower) <= 5 && (strings.HasSuffix(lower, "_") || strings.HasSuffix(lower, "-")) {
			note(problem{
				one:  "is short and ends in a separator. The keyword check looks for this text anywhere, including in the middle of a longer word",
				many: "are short and end in a separator. The keyword check looks for this text anywhere, including in the middle of a longer word",
			}, kw)
		}
		// These two name other detectors, so they stay per-keyword.
		if owners := sc.kwOwners[lower]; len(owners) > 1 {
			out = append(out, fmt.Sprintf("%q is also used by %d other detector(s): %s. Every match starts up all of them",
				kw, len(owners)-1, strings.Join(uniqueOwners(owners), ", ")))
		}
		if hosts := containingKeywords(sc, lower); len(hosts) > 0 {
			out = append(out, fmt.Sprintf("%q appears inside %d other keyword(s) (%s), so it matches everywhere they do, and more",
				kw, len(hosts), strings.Join(truncate(hosts, 4), ", ")))
		}
	}

	grouped := make([]string, 0, len(order))
	for _, p := range order {
		kws := byProblem[p]
		text := p.one
		if len(kws) > 1 {
			text = p.many
		}
		grouped = append(grouped, strings.Join(kws, ", ")+" "+text)
	}
	return append(grouped, out...)
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
