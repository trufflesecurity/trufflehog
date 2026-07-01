package seedphrase

import (
	"strings"

	regexp "github.com/wasilibs/go-re2"
)

var wordPat = regexp.MustCompile(`[a-zA-Z]+`)

// Candidate is a normalized seed phrase window found in tokenized input.
type Candidate struct {
	Start  int
	End    int
	Phrase string
}

// NormalizeWords extracts ASCII alphabetic tokens and lowercases them.
func NormalizeWords(data []byte) []string {
	tokens := wordPat.FindAllString(string(data), -1)
	words := make([]string, len(tokens))
	for i, token := range tokens {
		words[i] = strings.ToLower(token)
	}
	return words
}

// HasOnlyOneUniqueWord reports whether a non-empty word window repeats one word.
func HasOnlyOneUniqueWord(words []string) bool {
	if len(words) == 0 {
		return false
	}

	first := words[0]
	for _, word := range words[1:] {
		if word != first {
			return false
		}
	}
	return true
}

// FindCandidates scans words left-to-right for valid seed phrase windows.
func FindCandidates(words []string, lengths []int, valid func([]string) bool) []Candidate {
	if len(lengths) == 0 {
		return nil
	}

	minLength := lengths[0]
	for _, length := range lengths[1:] {
		if length < minLength {
			minLength = length
		}
	}
	if len(words) < minLength {
		return nil
	}

	seen := make(map[string]struct{})
	candidates := []Candidate{}
	for start := 0; start <= len(words)-minLength; start++ {
		for _, length := range lengths {
			if start+length > len(words) {
				continue
			}

			phraseWords := words[start : start+length]
			if HasOnlyOneUniqueWord(phraseWords) || !valid(phraseWords) {
				continue
			}

			phrase := strings.Join(phraseWords, " ")
			if _, ok := seen[phrase]; ok {
				continue
			}
			seen[phrase] = struct{}{}
			candidates = append(candidates, Candidate{
				Start:  start,
				End:    start + length,
				Phrase: phrase,
			})
			break
		}
	}

	return candidates
}

// RemoveContainedCandidates removes candidates fully contained in longer candidates.
func RemoveContainedCandidates(candidates []Candidate) []Candidate {
	results := make([]Candidate, 0, len(candidates))
	for i, candidate := range candidates {
		if isContainedInLongerCandidate(candidate, candidates[:i]) ||
			isContainedInLongerCandidate(candidate, candidates[i+1:]) {
			continue
		}
		results = append(results, candidate)
	}
	return results
}

func isContainedInLongerCandidate(candidate Candidate, others []Candidate) bool {
	for _, other := range others {
		if other.Start <= candidate.Start &&
			candidate.End <= other.End &&
			other.End-other.Start > candidate.End-candidate.Start {
			return true
		}
	}
	return false
}
