package generic

// cat scanner/pkg/secrets/generic/top-1000.txt | awk 'length($0)>5' > scanner/pkg/secrets/generic/words.txt

import (
	"context"
	"encoding/base64"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func New() Scanner {
	excludePatterns := []string{
		`[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}`,                                    // UUID
		`[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}`, // UUIDv4
		`[A-Z]{2,6}\-[0-9]{2,6}`, // issue tracker
		`#[a-fA-F0-9]{6}\b`,      // hex color code
		`\b[A-Fa-f0-9]{64}\b`,    // hex encoded hash
		`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`, // http
		`\b([/]{0,1}([\w]+[/])+[\w\.]*)\b`,                 // filepath
		`([0-9A-F]{2}[:-]){5}([0-9A-F]{2})`,                // MAC addr
		`\d{4}[-/]{1}([0]\d|1[0-2])[-/]{1}([0-2]\d|3[01])`, // date
		`[v|\-]\d\.\d`, // version
		`\d\.\d\.\d-`,  // version
		`[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}`,      // IPs and OIDs
		`[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}`, // hex encoding
		`[\w]+\([\w, ]+\)`, // function
	}

	var excludeMatchers []*regexp.Regexp
	for _, pat := range excludePatterns {
		excludeMatchers = append(excludeMatchers, regexp.MustCompile(pat))
	}

	return Scanner{
		excludeMatchers: excludeMatchers,
	}
}

type Scanner struct {
	excludeMatchers []*regexp.Regexp
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var keywords = []string{"pass", "token", "cred", "secret", "key"}

var (
	// \x21-\x7e == ASCII 33 (0x21) and 126 (0x7e)
	keyPat = regexp.MustCompile(detectors.PrefixRegex(keywords) + `(\b[\x21-\x7e]{16,64}\b)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return keywords
}

// FromData will find and optionally verify Generic secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		token := match[1]

		// Least expensive-> most expensive filters.
		// Substrings, then patterns.

		if detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		// toss any that match regexes
		if hasReMatch(s.excludeMatchers, token) {
			continue
		}

		// clean up containment chars
		token = strings.Trim(token, fmt.Sprintf(`%s" '.,)(][}{`, "`"))

		// toss any that b64 decode
		// TODO: run them through again?
		_, err := base64.StdEncoding.DecodeString(token)
		if err == nil {
			continue
		}

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Generic,
			Raw:          []byte(token),
		}

		results = append(results, s)
	}

	return
}

func hasReMatch(matchers []*regexp.Regexp, token string) bool {
	for _, m := range matchers {
		if m.MatchString(token) {
			return true
		}
	}
	return false
}

// func hasDictWord(wordList []string, token string) bool {
// 	lower := strings.ToLower(token)
// 	for _, word := range wordList {
// 		if strings.Contains(lower, word) {
// 			return true
// 		}
// 	}
// 	return false
// }

// func bytesToCleanWordList(data []byte) []string {
// 	words := []string{}
// 	for _, word := range strings.Split(string(data), "\n") {
// 		if strings.TrimSpace(word) != "" {
// 			words = append(words, strings.TrimSpace(strings.ToLower(word)))
// 		}
// 	}
// 	return words
// }

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Generic
}
