package generic

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

func New() Scanner {
	excludePatterns := [][]byte{
		[]byte(`[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}`),                                    // UUID
		[]byte(`[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}`), // UUIDv4
		[]byte(`[A-Z]{2,6}\-[0-9]{2,6}`),                                                                  // issue tracker
		[]byte(`#[a-fA-F0-9]{6}\b`),
		[]byte(`\b[A-Fa-f0-9]{64}\b`),
		[]byte(`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`),
		[]byte(`\b([/]{0,1}([\w]+[/])+[\w\.]*)\b`),
		[]byte(`([0-9A-F]{2}[:-]){5}([0-9A-F]{2})`),
		[]byte(`\d{4}[-/]{1}([0]\d|1[0-2])[-/]{1}([0-2]\d|3[01])`),
		[]byte(`[v|\-]\d\.\d`),
		[]byte(`\d\.\d\.\d-`),
		[]byte(`[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}`),
		[]byte(`[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}:[A-Fa-f0-9x]{2}`),
		[]byte(`[\w]+\([\w, ]+\)`),
	}

	excludeMatchers := []*regexp.Regexp{}
	for _, pat := range excludePatterns {
		excludeMatchers = append(excludeMatchers, regexp.MustCompile(string(pat)))
	}

	return Scanner{
		excludeMatchers: excludeMatchers,
	}
}

type Scanner struct {
	excludeMatchers []*regexp.Regexp
}

var _ detectors.Detector = (*Scanner)(nil)

var keywords = [][]byte{[]byte("pass"), []byte("token"), []byte("cred"), []byte("secret"), []byte("key")}

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex(keywords) + `(\b[\x21-\x7e]{16,64}\b)`)
)

func (s Scanner) Keywords() [][]byte {
	return keywords
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		token := match[1]

		if detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		if hasReMatch(s.excludeMatchers, token) {
			continue
		}

		token = bytes.Trim(token, []byte(fmt.Sprintf(`%s" '.,)(][}{`, "`")))

		_, err := base64.StdEncoding.DecodeString(string(token))
		if err == nil {
			continue
		}

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Generic,
			Raw:          token,
		}

		results = append(results, s)
	}

	return
}

func hasReMatch(matchers []*regexp.Regexp, token []byte) bool {
	for _, m := range matchers {
		if m.Match(token) {
			return true
		}
	}
	return false
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Generic
}
