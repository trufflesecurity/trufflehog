package github

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	v1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/github/v1"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	v1.Scanner
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)
var _ detectors.MaxSecretSizeProvider = (*Scanner)(nil)

func (s Scanner) Version() int {
	return 2
}
func (Scanner) CloudEndpoint() string { return "https://api.github.com" }

// MaxSecretSize overrides the engine's default 512-byte keyword window so complete
// GitHub App installation tokens are passed to FromData.
func (Scanner) MaxSecretSize() int64 { return 4096 }

var (
	// Oauth token
	// https://developer.github.com/v3/#oauth2-token-sent-in-a-header
	// Token type list:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	// https://github.blog/changelog/2022-10-18-introducing-fine-grained-personal-access-tokens/
	// GitHub App installation tokens use the ghs_APPID_JWT format:
	// https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-format-for-github-app-installation-tokens/
	keyPat = regexp.MustCompile(`\b(ghs_[0-9]+_eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+|(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}\b)`)

	// TODO: Oauth2 client_id and client_secret
	// https://developer.github.com/v3/#oauth2-keysecret

	// tokenTypesByPrefix maps each GitHub token prefix to a human-readable type.
	// Each prefix identifies a materially different credential (PAT, OAuth
	// grant, or GitHub App token) that is revoked/rotated through a different
	// GitHub settings page.
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	tokenTypesByPrefix = map[string]string{
		"ghp_":        "Personal Access Token (classic)",
		"github_pat_": "Personal Access Token (fine-grained)",
		"gho_":        "OAuth Access Token",
		"ghu_":        "GitHub App User-to-Server Token",
		"ghs_":        "GitHub App Server-to-Server (installation) Token",
		"ghr_":        "GitHub App Refresh Token",
	}
)

// githubTokenType returns the human-readable token type for a matched token,
// keyed off its prefix. Falls back to a generic label if no known prefix
// matches (should not happen given keyPat, but keeps this safe).
func githubTokenType(token string) string {
	for prefix, tokenType := range tokenTypesByPrefix {
		if strings.HasPrefix(token, prefix) {
			return tokenType
		}
	}
	return "Unknown GitHub token"
}

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

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Github,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
				"version":        fmt.Sprintf("%d", s.Version()),
				"token_type":     githubTokenType(token),
			},
			SecretParts: map[string]string{"key": token},
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

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Github
}

func (s Scanner) Description() string {
	return "GitHub is a platform for version control and collaboration. Personal access tokens (PATs) can be used to access and modify repositories and other resources."
}
