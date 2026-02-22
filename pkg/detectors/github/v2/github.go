package github

import (
	"context"
	"fmt"
	"hash/crc32"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/github/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	v1.Scanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

func (s Scanner) Version() int {
	return 2
}
func (Scanner) CloudEndpoint() string { return "https://api.github.com" }

var (
	// Oauth token
	// https://developer.github.com/v3/#oauth2-token-sent-in-a-header
	// Token type list:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	// https://github.blog/changelog/2022-10-18-introducing-fine-grained-personal-access-tokens/
	keyPat = regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`)

	// TODO: Oauth2 client_id and client_secret
	// https://developer.github.com/v3/#oauth2-keysecret
)

var classicTokenPrefixes = []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}
}

// FromData will find and optionally verify GitHub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		// First match is entire regex, second is the first group.

		token := match[1]
		if isClassicGitHubToken(token) && !hasValidClassicGitHubChecksum(token) {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
				"version":        fmt.Sprintf("%d", s.Version()),
			},
			AnalysisInfo: map[string]string{"key": token},
		}

		if verify {
			client := common.SaneHttpClient()

			isVerified, userResponse, headers, err := s.VerifyGithub(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(err, token)

			if userResponse != nil {
				v1.SetUserResponse(userResponse, &s1)
			}
			if headers != nil {
				v1.SetHeaderInfo(headers, &s1)
			}
		}

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}

func (s Scanner) Description() string {
	return "GitHub is a platform for version control and collaboration. Personal access tokens (PATs) can be used to access and modify repositories and other resources."
}

func isClassicGitHubToken(token string) bool {
	if len(token) != 40 {
		return false
	}
	for _, prefix := range classicTokenPrefixes {
		if strings.HasPrefix(token, prefix) {
			return true
		}
	}
	return false
}

func hasValidClassicGitHubChecksum(token string) bool {
	// Format: <prefix><30-char body><6-char checksum>, total length 40.
	body := token[4:34]
	actualChecksum := token[34:]
	expectedChecksum := base62EncodePadded(uint64(crc32.ChecksumIEEE([]byte(body))), 6)
	return actualChecksum == expectedChecksum
}

func base62EncodePadded(value uint64, width int) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	if width <= 0 {
		width = 1
	}

	var encoded string
	if value == 0 {
		encoded = "0"
	} else {
		out := make([]byte, 0, 11)
		for value > 0 {
			out = append(out, alphabet[value%62])
			value /= 62
		}
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
		encoded = string(out)
	}

	if len(encoded) >= width {
		return encoded
	}
	return strings.Repeat("0", width-len(encoded)) + encoded
}
