package detectors

import (
	_ "embed"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

var DefaultFalsePositives = []FalsePositive{"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "www"}

type FalsePositive string

//go:embed "badlist.txt"
var badList []byte

//go:embed "words.txt"
var wordList []byte

//go:embed "programmingbooks.txt"
var programmingBookWords []byte

var filter *ahocorasick.Trie

func init() {
	builder := ahocorasick.NewTrieBuilder()

	wordList := bytesToCleanWordList(wordList)
	builder.AddStrings(wordList)

	badList := bytesToCleanWordList(badList)
	builder.AddStrings(badList)

	programmingBookWords := bytesToCleanWordList(programmingBookWords)
	builder.AddStrings(programmingBookWords)

	filter = builder.Build()
}

// IsKnownFalsePositives will not return a valid secret finding if any of the disqualifying conditions are met
// Currently that includes: No number, english word in key, or matches common example pattens.
// Only the secret key material should be passed into this function
func IsKnownFalsePositive(match string, falsePositives []FalsePositive, wordCheck bool) bool {
	if !utf8.ValidString(match) {
		return true
	}
	lower := strings.ToLower(match)
	for _, fp := range falsePositives {
		if strings.Contains(lower, string(fp)) {
			return true
		}
	}

	if wordCheck {
		if filter.MatchFirstString(lower) != nil {
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
	words := make(map[string]struct{})
	for _, word := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(word) != "" {
			words[strings.TrimSpace(strings.ToLower(word))] = struct{}{}
		}
	}

	wordList := make([]string, 0, len(words))
	for word := range words {
		wordList = append(wordList, word)
	}
	return wordList
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
	var filteredResults []Result
	for _, result := range results {
		if !result.Verified {
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
