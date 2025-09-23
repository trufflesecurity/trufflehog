package detectors

import (
	_ "embed"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"gopkg.in/yaml.v3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
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

// AllowlistEntry represents an allowlist entry in the YAML config
type AllowlistEntry struct {
	Description string   `yaml:"description,omitempty"` // Optional description for the allowlist
	Values      []string `yaml:"values"`                // List of secret patterns/regexes to allowlist
}

// CompiledAllowlist holds both exact string matches and compiled regex patterns for efficient matching
type CompiledAllowlist struct {
	ExactMatches    map[string]struct{} // For exact string matching (O(1) lookup)
	CompiledRegexes []*regexp.Regexp    // Pre-compiled regex patterns
	RegexPatterns   []string            // Original regex patterns (for logging/debugging)
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

// FilterAllowlistedSecrets filters out results that match allowlisted secrets.
// This allows users to specify known safe secrets that should not be reported.
// Supports regex patterns.
func FilterAllowlistedSecrets(ctx context.Context, results []Result, allowlist *CompiledAllowlist) []Result {
	if allowlist == nil || (len(allowlist.ExactMatches) == 0 && len(allowlist.CompiledRegexes) == 0) {
		return results
	}

	return slices.DeleteFunc(results, func(result Result) bool {
		if len(result.Raw) == 0 {
			return false // Keep results with empty Raw
		}

		// Check if the raw secret matches any allowlisted secret
		rawSecret := string(result.Raw)
		log.RedactGlobally(rawSecret)
		if isAllowlisted, matchReason := isSecretAllowlisted(rawSecret, allowlist); isAllowlisted {
			ctx.Logger().V(4).Info("Skipping result: allowlisted secret", "result", rawSecret, "reason", matchReason)
			return true // Delete this result
		}

		// Also check RawV2 if present
		if result.RawV2 != nil {
			rawV2Secret := string(result.RawV2)
			if isAllowlisted, matchReason := isSecretAllowlisted(rawV2Secret, allowlist); isAllowlisted {
				ctx.Logger().V(4).Info("Skipping result: allowlisted secret", "result", rawV2Secret, "reason", matchReason)
				return true // Delete this result
			}
		}

		return false // Keep this result
	})
}

// LoadAllowlistedSecrets loads secrets from a YAML file that should be allowlisted.
// The YAML format supports multiline secrets and includes optional descriptions.
// Returns a CompiledAllowlist with pre-compiled regex patterns for efficient matching.
func LoadAllowlistedSecrets(yamlFile string) ([]AllowlistEntry, error) {
	file, err := os.Open(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open allowlist file: %w", err)
	}
	defer file.Close()

	// Read the entire file content
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read allowlist file: %w", err)
	}

	var allowList []AllowlistEntry
	if err := yaml.Unmarshal(content, &allowList); err != nil {
		return nil, fmt.Errorf("failed to parse YAML allowlist file: %w", err)
	}

	return allowList, nil
}

// CompileAllowlistPatterns compiles a list of patterns into a CompiledAllowlist.
// All patterns are first attempted to be compiled as regex. If compilation fails,
// they are treated as exact string matches.
func CompileAllowlistPatterns(allowList []AllowlistEntry) *CompiledAllowlist {
	allowlist := &CompiledAllowlist{
		ExactMatches:    make(map[string]struct{}, 0),
		CompiledRegexes: make([]*regexp.Regexp, 0),
		RegexPatterns:   make([]string, 0),
	}

	for _, entry := range allowList {
		for _, pattern := range entry.Values {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue // Skip empty patterns
			}

			// Always try to compile as regex first
			if compiledRegex, err := regexp.Compile(pattern); err == nil {
				// Successfully compiled as regex
				allowlist.CompiledRegexes = append(allowlist.CompiledRegexes, compiledRegex)
				allowlist.RegexPatterns = append(allowlist.RegexPatterns, pattern)
			} else {
				// Invalid regex, treat as exact string match
				allowlist.ExactMatches[pattern] = struct{}{}
			}
		}
	}

	return allowlist
}

// isSecretAllowlisted checks if a secret matches any allowlisted pattern (exact string or regex)
func isSecretAllowlisted(secret string, allowlist *CompiledAllowlist) (bool, string) {
	if allowlist == nil {
		return false, ""
	}

	// Trim all whitespace (spaces, tabs, newlines, carriage returns) from the secret
	secret = strings.TrimSpace(secret)

	// First, try exact string matching for performance (O(1) lookup)
	if _, isAllowlisted := allowlist.ExactMatches[secret]; isAllowlisted {
		return true, "exact match"
	}

	// Try pre-compiled regex patterns
	for i, compiledRegex := range allowlist.CompiledRegexes {
		if compiledRegex.MatchString(secret) {
			return true, "regex match: " + allowlist.RegexPatterns[i]
		}
	}

	return false, ""
}
