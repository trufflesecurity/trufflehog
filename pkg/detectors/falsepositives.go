package detectors

import (
	_ "embed"
	"math"
	"strings"
	"unicode"
)

var DefaultFalsePositives = []FalsePositive{"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "www"}

type FalsePositive string

//go:embed "badlist.txt"
var badList []byte

//go:embed "words.txt"
var wordList []byte

//go:embed "programmingbooks.txt"
var programmingBookWords []byte

type Wordlists struct {
	wordList             []string
	badList              []string
	programmingBookWords []string
}

var FalsePositiveWordlists = Wordlists{
	wordList:             bytesToCleanWordList(wordList),
	badList:              bytesToCleanWordList(badList),
	programmingBookWords: bytesToCleanWordList(programmingBookWords),
}

// IsKnownFalsePositives will not return a valid secret finding if any of the disqualifying conditions are met
// Currently that includes: No number, english word in key, or matches common example pattens.
// Only the secret key material should be passed into this function
func IsKnownFalsePositive(match string, falsePositives []FalsePositive, wordCheck bool) bool {

	for _, fp := range falsePositives {
		if strings.Contains(strings.ToLower(match), string(fp)) {
			return true
		}
	}

	if wordCheck {
		// check against common substring badlist
		if hasDictWord(FalsePositiveWordlists.badList, match) {
			return true
		}

		// check for dictionary word substrings
		if hasDictWord(FalsePositiveWordlists.wordList, match) {
			return true
		}

		// check for programming book token substrings
		if hasDictWord(FalsePositiveWordlists.programmingBookWords, match) {
			return true
		}
	}
	return false
}

func hasDictWord(wordList []string, token string) bool {
	lower := strings.ToLower(token)
	for _, word := range wordList {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

func HasDigit(key string) bool {
	for _, ch := range key {
		if unicode.IsDigit(ch) {
			return true
		}
	}

	return false
}

func bytesToCleanWordList(data []byte) []string {
	words := []string{}
	for _, word := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(word) != "" {
			words = append(words, strings.TrimSpace(strings.ToLower(word)))
		}
	}
	return words
}

func StringShannonEntropy(input string) float64 {
	chars := make(map[rune]float64)
	inverseTotal := 1 / float64(len(input)) // precompute the inverse

	for _, char := range input {
		chars[char]++
	}

	entropy := 0.0
	for _, count := range chars {
		probability := count * inverseTotal
		entropy += probability * math.Log2(probability)
	}

	return -entropy
}

// FilterResultsWithEntropy filters out determinately unverified results that have a shannon entropy below the given value.
func FilterResultsWithEntropy(results []Result, entropy float64) []Result {
	filteredResults := []Result{}
	for _, result := range results {
		if !result.Verified && result.VerificationError == nil {
			if result.RawV2 != nil {
				if StringShannonEntropy(string(result.RawV2)) >= entropy {
					filteredResults = append(filteredResults, result)
				}
			} else {
				if StringShannonEntropy(string(result.Raw)) >= entropy {
					filteredResults = append(filteredResults, result)
				}
			}
		}
	}
	return filteredResults
}
