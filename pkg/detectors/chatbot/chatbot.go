package chatbot

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"chatbot"}) + `\b([a-zA-Z0-9_]{32})\b`)

	// False positive filters
	onlyLetters    = regexp.MustCompile(`^[a-zA-Z]+$`)
	snakeCaseOnly  = regexp.MustCompile(`^[a-z]+(_[a-z]+)+$`)
	camelCaseName  = regexp.MustCompile(`^[a-z]+([A-Z][a-z]+)+$`) // camelCase
	pascalCaseName = regexp.MustCompile(`^([A-Z][a-z]+)+$`)       // PascalCase
)

// isLikelyFalsePositive checks if a matched string is likely a false positive
// (e.g., variable names, class names, identifiers) rather than an actual API key.
func isLikelyFalsePositive(key string) bool {
	// Only letters (no digits) - likely variable/class name
	if onlyLetters.MatchString(key) {
		return true
	}
	// Snake_case pattern - likely variable name
	if snakeCaseOnly.MatchString(key) {
		return true
	}
	// camelCase or PascalCase - likely code identifier
	if camelCaseName.MatchString(key) || pascalCaseName.MatchString(key) {
		return true
	}
	return false
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"chatbot"}
}

// FromData will find and optionally verify Chatbot secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		// Filter out likely false positives
		if isLikelyFalsePositive(resMatch) {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Chatbot,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.chatbot.com/stories", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer func() {
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()
				}()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Chatbot
}

func (s Scanner) Description() string {
	return "Chatbot API keys are used to interact with the Chatbot service, allowing access to create, modify, and retrieve chatbot stories and other resources."
}
