package detectors

import (
	"bytes"
	_ "embed"
	"unicode"
)

// var DefaultFalsePositives = []FalsePositive{"example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "www"}
//
// type FalsePositive string

var DefaultFalsePositives = []FalsePositive{[]byte("example"), []byte("xxxxxx"), []byte("aaaaaa"), []byte("abcde"), []byte("00000"), []byte("sample"), []byte("www")}

type FalsePositive []byte

//go:embed "badlist.txt"
var badList []byte

//go:embed "words.txt"
var wordList []byte

//go:embed "programmingbooks.txt"
var programmingBookWords []byte

type Wordlists struct {
	wordList             [][]byte
	badList              [][]byte
	programmingBookWords [][]byte
}

var FalsePositiveWordlists = Wordlists{
	wordList:             bytesToCleanWordList(wordList),
	badList:              bytesToCleanWordList(badList),
	programmingBookWords: bytesToCleanWordList(programmingBookWords),
}

// IsKnownFalsePositives will not return a valid secret finding if any of the disqualifying conditions are met
// Currently that includes: No number, english word in key, or matches common example pattens.
// Only the secret key material should be passed into this function
func IsKnownFalsePositive(match []byte, falsePositives []FalsePositive, wordCheck bool) bool {
	matchLower := bytes.ToLower(match)
	for _, fp := range falsePositives {
		if bytes.Contains(matchLower, fp) {
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

func hasDictWord(wordList [][]byte, token []byte) bool {
	lower := bytes.ToLower(token)
	for _, word := range wordList {
		if bytes.Contains(lower, word) {
			return true
		}
	}
	return false
}

func HasDigit(key []byte) bool {
	for _, ch := range string(key) {
		if unicode.IsDigit(ch) {
			return true
		}
	}
	return false
}

func bytesToCleanWordList(data []byte) [][]byte {
	words := [][]byte{}
	for _, word := range bytes.Split(data, []byte("\n")) {
		trimmedWord := bytes.TrimSpace(word)
		if len(trimmedWord) != 0 {
			words = append(words, bytes.ToLower(trimmedWord))
		}
	}
	return words
}
