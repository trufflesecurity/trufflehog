package detectors

import (
	"bufio"
	_ "embed"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	ahocorasick "github.com/BobuSumisu/aho-corasick"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var (
	DefaultFalsePositives = map[FalsePositive]struct{}{
		"example": {}, "xxxxxx": {}, "aaaaaa": {}, "abcde": {}, "00000": {}, "sample": {}, "*****": {},
	}
	UuidFalsePositives map[FalsePositive]struct{}
)

type FalsePositive string

type CustomFalsePositiveChecker interface {
	// IsFalsePositive returns two values:
	// 1. Whether the result is a false positive.
	// 2. If #1 is `true`, the reason why.
	IsFalsePositive(result Result) (bool, string)
}

var (
	filter *ahocorasick.Trie

	//go:embed "fp_badlist.txt"
	badList []byte
	//go:embed "fp_words.txt"
	wordList []byte
	//go:embed "fp_programmingbooks.txt"
	programmingBookWords []byte
	//go:embed "fp_uuids.txt"
	uuidList []byte
)

func init() {
	// Populate trie.
	builder := ahocorasick.NewTrieBuilder()

	wordList := bytesToCleanWordList(wordList)
	builder.AddStrings(wordList)

	badList := bytesToCleanWordList(badList)
	builder.AddStrings(badList)

	programmingBookWords := bytesToCleanWordList(programmingBookWords)
	builder.AddStrings(programmingBookWords)

	uuidList := bytesToCleanWordList(uuidList)
	builder.AddStrings(uuidList)

	filter = builder.Build()

	// Populate custom FalsePositive list
	UuidFalsePositives = make(map[FalsePositive]struct{}, len(uuidList))
	for _, uuid := range uuidList {
		UuidFalsePositives[FalsePositive(uuid)] = struct{}{}
	}
}

func GetFalsePositiveCheck(detector Detector) func(Result) (bool, string) {
	checker, ok := detector.(CustomFalsePositiveChecker)
	if ok {
		return checker.IsFalsePositive
	}

	return func(res Result) (bool, string) {
		return IsKnownFalsePositive(string(res.Raw), DefaultFalsePositives, true)
	}
}

// IsKnownFalsePositive returns whether a finding is (likely) a known false positive, and the reason for the detection.
//
// Currently, this includes: english word in key or matches common example patterns.
// Only the secret key material should be passed into this function
func IsKnownFalsePositive(match string, falsePositives map[FalsePositive]struct{}, wordCheck bool) (bool, string) {
	if !utf8.ValidString(match) {
		return true, "invalid utf8"
	}
	lower := strings.ToLower(match)

	if _, exists := falsePositives[FalsePositive(lower)]; exists {
		return true, "matches term: " + lower
	}

	for fp := range falsePositives {
		fps := string(fp)
		if strings.Contains(lower, fps) {
			return true, "contains term: " + fps
		}
	}

	if wordCheck {
		if m := filter.MatchFirstString(lower); m != nil {
			return true, "matches wordlist: " + m.MatchString()
		}
	}

	return false, ""
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
func FilterKnownFalsePositives(ctx context.Context, detector Detector, results []Result) []Result {
	var filteredResults []Result

	isFalsePositive := GetFalsePositiveCheck(detector)

	for _, result := range results {
		if len(result.Raw) == 0 {
			ctx.Logger().Error(fmt.Errorf("empty raw"), "Skipping result: invalid")
			continue
		}

		if result.Verified {
			filteredResults = append(filteredResults, result)
			continue
		}

		if isFp, reason := isFalsePositive(result); isFp {
			ctx.Logger().V(4).Info("Skipping result: false positive", "result", string(result.Raw), "reason", reason)
			continue
		}
		filteredResults = append(filteredResults, result)
	}

	return filteredResults
}

// FilterWhitelistedSecrets filters out results that match whitelisted secrets.
// This allows users to specify known safe secrets that should not be reported.
// Supports regex patterns.
func FilterWhitelistedSecrets(ctx context.Context, results []Result, whitelistedSecrets map[string]struct{}) []Result {
	if len(whitelistedSecrets) == 0 {
		return results
	}

	var filteredResults []Result
	for _, result := range results {
		if len(result.Raw) == 0 {
			filteredResults = append(filteredResults, result)
			continue
		}

		isWhitelisted := false
		var matchReason string

		// Check if the raw secret matches any whitelisted secret
		rawSecret := string(result.Raw)
		if isWhitelisted, matchReason = isSecretWhitelisted(rawSecret, whitelistedSecrets); isWhitelisted {
			ctx.Logger().V(4).Info("Skipping result: whitelisted secret", "result", maskSecret(rawSecret), "reason", matchReason)
			continue
		}

		// Also check RawV2 if present
		if result.RawV2 != nil {
			rawV2Secret := string(result.RawV2)
			if isWhitelisted, matchReason = isSecretWhitelisted(rawV2Secret, whitelistedSecrets); isWhitelisted {
				ctx.Logger().V(4).Info("Skipping result: whitelisted secret", "result", maskSecret(rawV2Secret), "reason", matchReason)
				continue
			}
		}

		filteredResults = append(filteredResults, result)
	}

	return filteredResults
}

// loadWhitelistedSecrets loads secrets from a file that should be whitelisted
func LoadWhitelistedSecrets(filename string) (map[string]struct{}, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open whitelist file: %w", err)
	}
	defer file.Close()

	whitelistedSecrets := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		secret := strings.TrimSpace(scanner.Text())
		if secret != "" { // Skip empty lines
			whitelistedSecrets[secret] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading whitelist file: %w", err)
	}

	return whitelistedSecrets, nil
}

// isSecretWhitelisted checks if a secret matches any whitelisted pattern (exact string or regex)
func isSecretWhitelisted(secret string, whitelistedSecrets map[string]struct{}) (bool, string) {
	// First, try exact string matching for performance
	if _, isWhitelisted := whitelistedSecrets[secret]; isWhitelisted {
		return true, "exact match"
	}

	// Try regex matching
	for pattern := range whitelistedSecrets {
		if regex, err := regexp.Compile(pattern); err == nil {
			if regex.MatchString(secret) {
				return true, "regex match: " + pattern
			}
		}
	}

	return false, ""
}

// maskSecret masks a secret for safe logging by showing only the first and last few characters
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	if len(secret) <= 16 {
		return secret[:2] + "***" + secret[len(secret)-2:]
	}
	return secret[:4] + "***" + secret[len(secret)-4:]
}
