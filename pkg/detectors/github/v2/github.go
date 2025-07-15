package github

import (
	"context"
	"fmt"
	"net/http"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
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
	client = common.SaneHttpClient()
	// Oauth token
	// https://developer.github.com/v3/#oauth2-token-sent-in-a-header
	// Token type list:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	// https://github.blog/changelog/2022-10-18-introducing-fine-grained-personal-access-tokens/
	keyPat = regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`)

	// TODO: Oauth2 client_id and client_secret
	// https://developer.github.com/v3/#oauth2-keysecret

	credsCache = simple.NewCache(simple.WithExpirationInterval[detectors.CachedVerificationResult](1*time.Hour),
		simple.WithPurgeInterval[detectors.CachedVerificationResult](1*time.Hour))
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}

func (s Scanner) Description() string {
	return "GitHub is a platform for version control and collaboration. Personal access tokens (PATs) can be used to access and modify repositories and other resources."
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
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
				"version":        fmt.Sprintf("%d", s.Version()),
			},
			AnalysisInfo: map[string]string{"key": token},
		}

		if verify {
			s.verifyOrGetCachedResult(ctx, client, token, &s1)
		}

		results = append(results, s1)
	}

	return
}

// verifyOrGetCachedResult checks the cache for a verification result for the given secret and updates the result's verification fields.
// If no cached result exists, it verifies the secret using the GitHub API and caches the result.
// Uses per-secret locking to prevent concurrent verifications of the same secret.
func (s Scanner) verifyOrGetCachedResult(ctx context.Context, client *http.Client, token string, result *detectors.Result) {
	secretHash := detectors.ComputeXXHash(result.Raw)

	// acquire lock for this specific secret
	lock := detectors.GetOrCreateLock(secretHash)
	lock.Lock()
	defer lock.Unlock()

	// check if result for the secret is cached already
	credData, exist := credsCache.Get(secretHash)
	if exist {
		result.Verified = credData.Verified
		result.SetVerificationError(credData.VerificationErr)
		result.VerificationFromCache = true

		detectors.CleanupLock(secretHash)

		return
	}

	// if not cached, verify the secret using github API
	isVerified, userResponse, headers, err := s.VerifyGithub(ctx, client, token)
	result.Verified = isVerified
	result.SetVerificationError(err, token)

	if userResponse != nil {
		v1.SetUserResponse(userResponse, result)
	}
	if headers != nil {
		v1.SetHeaderInfo(headers, result)
	}

	credsCache.Set(detectors.ComputeXXHash(result.Raw), detectors.CachedVerificationResult{
		Verified:        result.Verified,
		VerificationErr: result.VerificationError(),
	})

	detectors.CleanupLock(secretHash)
}
