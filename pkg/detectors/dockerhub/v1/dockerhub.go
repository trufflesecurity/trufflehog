package dockerhub

import (
	"context"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/dockerhub/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

func (s Scanner) Version() int { return 1 }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	// Can use email or username for login.
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"docker"}) + `(?im)(?:user|usr|username|-u|id)(?:['"]?\s*[:=]\s*['"]?|[\s]+)([a-zA-Z0-9]{4,40})['"]?(?:\s|$|[,}])`)
	emailPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"docker"}) + common.EmailPattern)

	// Can use password or personal access token (PAT) for login, but this scanner will only check for PATs.
	accessTokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"docker", "-p"}) + `\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)

	// Pattern to exclude Docker protocol headers
	excludeHeaderPat = regexp.MustCompile(`(?i)(?:docker[-_]?upload[-_]?uuid|x[-_]?docker[-_]?upload[-_]?uuid|docker[-_]?content[-_]?digest)\s*:\s*([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"docker"}
}

// FromData will find and optionally verify Dockerhub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// First, find and exclude Docker protocol headers to avoid false positives
	excludedTokens := make(map[string]struct{})
	for _, matches := range excludeHeaderPat.FindAllStringSubmatch(dataStr, -1) {
		excludedTokens[matches[1]] = struct{}{}
	}

	// Deduplicate results and filter out excluded tokens.
	tokens := make(map[string]struct{})
	for _, matches := range accessTokenPat.FindAllStringSubmatch(dataStr, -1) {
		// Skip if this token was found in a Docker protocol header
		if _, excluded := excludedTokens[matches[1]]; !excluded {
			tokens[matches[1]] = struct{}{}
		}
	}
	if len(tokens) == 0 {
		return
	}

	usernames := make(map[string]struct{})
	for _, matches := range usernamePat.FindAllStringSubmatch(dataStr, -1) {
		// Additional validation: ensure username doesn't look like part of a UUID
		if !isLikelyUUIDFragment(matches[1]) {
			usernames[matches[1]] = struct{}{}
		}
	}
	for _, matches := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		usernames[matches[1]] = struct{}{}
	}

	// Process results.
	for token := range tokens {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
		}

		for username := range usernames {
			s1.RawV2 = []byte(fmt.Sprintf("%s:%s", username, token))

			if verify {
				if s.client == nil {
					s.client = common.SaneHttpClient()
				}

				isVerified, extraData, verificationErr := v2.VerifyMatch(ctx, s.client, username, token)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.ExtraData["version"] = fmt.Sprintf("%d", s.Version())
				s1.SetVerificationError(verificationErr)
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"username": username,
						"pat":      token,
					}
				}
			}

			results = append(results, s1)

			if s1.Verified {
				break
			}
		}

		// PAT matches without usernames cannot be verified but might still be useful.
		if len(usernames) == 0 {
			results = append(results, s1)
		}
	}
	return
}

// Helper function to detect if a string looks like a UUID fragment
func isLikelyUUIDFragment(s string) bool {
	// Check for UUID segment (8-4-4-4-12 format segments)
	if regexp.MustCompile(`^[a-f0-9]{8}$`).MatchString(s) ||
		regexp.MustCompile(`^[a-f0-9]{4}-?[a-f0-9]{4}$`).MatchString(s) {
		return true
	}

	// Check for numeric-only strings (common in correlation IDs)
	if regexp.MustCompile(`^\d{8,}$`).MatchString(s) {
		return true
	}

	// Check for full UUIDs
	if regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(s) {
		return true
	}

	return false
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dockerhub
}

func (s Scanner) Description() string {
	return "Docker is a platform used to develop, ship, and run applications. Docker access tokens can be used to authenticate and interact with Docker services."
}
