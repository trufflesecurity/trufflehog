package detectors

import (
	_ "embed"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
func FilterResultsWithEntropy(ctx context.Context, results []Result, entropy float64, shouldLog bool) []Result {
	var filteredResults []Result
	for _, result := range results {
		if !result.Verified {
			if result.Raw != nil {
				if StringShannonEntropy(string(result.Raw)) >= entropy {
					filteredResults = append(filteredResults, result)
				} else {
					if shouldLog {
						ctx.Logger().Info("Filtered out result with low entropy", "result", result)
					}
				}
			} else {
				filteredResults = append(filteredResults, result)
			}
		} else {
			filteredResults = append(filteredResults, result)
		}
	}
	return filteredResults
}

// FilterKnownFalsePositives filters out known false positives from the results.
func FilterKnownFalsePositives(ctx context.Context, results []Result, falsePositives []FalsePositive, wordCheck bool, shouldLog bool) []Result {
	var filteredResults []Result
	for _, result := range results {
		if !result.Verified {
			switch result.DetectorType {
			case detectorspb.DetectorType_CustomRegex:
				filteredResults = append(filteredResults, result)
			case detectorspb.DetectorType_GCP,
				detectorspb.DetectorType_URI,
				detectorspb.DetectorType_AzureBatch,
				detectorspb.DetectorType_AzureContainerRegistry,
				detectorspb.DetectorType_Shopify,
				detectorspb.DetectorType_Postgres,
				detectorspb.DetectorType_MongoDB,
				detectorspb.DetectorType_JDBC:
				filteredResults = append(filteredResults, result)
			default:
				if result.Raw != nil {
					if !IsKnownFalsePositive(string(result.Raw), falsePositives, wordCheck) {
						filteredResults = append(filteredResults, result)
					} else {
						if shouldLog {
							ctx.Logger().Info("Filtered out known false positive", "result", result)
						}
					}
				} else {
					filteredResults = append(filteredResults, result)
				}
			}
		} else {
			filteredResults = append(filteredResults, result)
		}
	}
	return filteredResults
}
