package metabase

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b([a-zA-Z0-9-]{36})\b`)

	baseURL = regexp.MustCompile(detectors.PrefixRegex([]string{"metabase"}) + `\b(https?:\/\/[-a-zA-Z0-9@:%._\+~#=]{7,256})\b`)
)

// isUrlSlug checks if a match is part of a URL slug/path.
// URL slugs often start with hyphens and contain descriptive words.
func isUrlSlug(dataStr string, match string, startIdx, endIdx int) bool {
	// Extract context around the match (±300 chars)
	contextStart := startIdx - 300
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endIdx + 300
	if contextEnd > len(dataStr) {
		contextEnd = len(dataStr)
	}
	context := dataStr[contextStart:contextEnd]

	// Check if match starts with hyphen (common in URL slugs)
	if strings.HasPrefix(match, "-") {
		// Check if it's within a URL pattern
		if strings.Contains(context, "http://") || strings.Contains(context, "https://") {
			matchPos := strings.Index(context, match)
			if matchPos > 0 {
				beforeMatch := context[:matchPos]
				// Check if there's a URL before the match
				if strings.Contains(beforeMatch, "http://") || strings.Contains(beforeMatch, "https://") ||
					strings.Contains(beforeMatch, "question/") || strings.Contains(beforeMatch, "/") {
					return true
				}
			}
		}
	}

	// Check if match contains common URL slug patterns (question IDs, paths)
	if strings.Contains(context, "/question/") || strings.Contains(context, "?partition_key=") ||
		strings.Contains(context, "?query=") || strings.Contains(context, "&") {
		matchPos := strings.Index(context, match)
		if matchPos > 0 {
			beforeMatch := context[:matchPos]
			// If it's after a URL path separator, it's likely a slug
			if strings.Contains(beforeMatch, "/") || strings.Contains(beforeMatch, "?") {
				return true
			}
		}
	}

	return false
}

// isDescriptiveString checks if a match contains descriptive/readable words.
// Real session tokens are random, not descriptive words like "journal", "deduplication", etc.
func isDescriptiveString(match string) bool {
	// Common descriptive words that appear in URL slugs but not in tokens
	descriptiveWords := []string{
		"journal", "deduplication", "voucher", "order", "number", "mapping",
		"service", "name", "identifier", "test", "example", "query", "question",
		"report", "dashboard", "analysis", "data", "export", "import",
	}

	matchLower := strings.ToLower(match)
	for _, word := range descriptiveWords {
		if strings.Contains(matchLower, word) {
			return true
		}
	}

	// Check if it's mostly lowercase letters with hyphens (descriptive slug pattern)
	// vs random alphanumeric (token pattern)
	hasLowercase := false
	hasUppercase := false
	hasDigits := false
	hyphenCount := 0

	for _, r := range match {
		if unicode.IsLower(r) {
			hasLowercase = true
		} else if unicode.IsUpper(r) {
			hasUppercase = true
		} else if unicode.IsDigit(r) {
			hasDigits = true
		} else if r == '-' {
			hyphenCount++
		}
	}

	// If it has many hyphens and is mostly lowercase, it's likely a descriptive slug
	// Real tokens typically have fewer hyphens and more mixed case/digits
	if hyphenCount >= 3 && hasLowercase && !hasUppercase && !hasDigits {
		return true
	}

	return false
}

// isLikelyFalsePositive checks if a matched string is likely a false positive.
func isLikelyFalsePositive(dataStr string, match string, startIdx, endIdx int) bool {
	// Filter 1: URL slug pattern (starts with hyphen, part of URL path)
	if isUrlSlug(dataStr, match, startIdx, endIdx) {
		return true
	}

	// Filter 2: Descriptive string (readable words, not random token)
	if isDescriptiveString(match) {
		return true
	}

	return false
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"metabase"}
}

// FromData will find and optionally verify Metabase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatchIndex(dataStr, -1)
	urlMatches := baseURL.FindAllStringSubmatch(dataStr, -1)

	for _, matchIdx := range matches {
		if len(matchIdx) < 4 {
			continue
		}
		resMatch := strings.TrimSpace(dataStr[matchIdx[2]:matchIdx[3]])

		// Filter out false positives
		if isLikelyFalsePositive(dataStr, resMatch, matchIdx[2], matchIdx[3]) {
			continue
		}

		for _, urlMatch := range urlMatches {
			resURLMatch := strings.TrimSpace(urlMatch[1])

			u, err := detectors.ParseURLAndStripPathAndParams(resURLMatch)
			if err != nil {
				// if the URL is invalid just move onto the next one
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Metabase,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resURLMatch),
			}

			if verify {
				u.Path = "/api/user/current"
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
				if err != nil {
					continue
				}
				req.Header.Add("X-Metabase-Session", resMatch)
				res, err := client.Do(req)
				if err == nil {
					defer func() {
						_, _ = io.Copy(io.Discard, res.Body)
						_ = res.Body.Close()
					}()
					body, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					if res.StatusCode == http.StatusOK && json.Valid(body) {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Metabase
}

func (s Scanner) Description() string {
	return "Metabase is an open-source business intelligence tool. Metabase session tokens can be used to access and interact with the Metabase API."
}
