package lambdatest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

const lambdatestAuthURL = "https://auth.lambdatest.com/api/user/token/auth"

var (
	defaultClient = common.SaneHttpClient()
	// LambdaTest access keys look like LT_ followed by 47 alphanumeric
	// characters. The keyword must be near the key, which keeps generic
	// config dumps from firing.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"lambdatest", "LT_ACCESS_KEY", "LT_AUTHKEY", "LAMBDATEST_ACCESS_KEY",
		"lambdatestKey", "accessKey", "ACCESS_KEY",
	}) + `\b(LT_[a-zA-Z0-9]{47})\b`)

	// A username alone is not a credential; it is only useful paired with an
	// access key, so it is captured keyword-bound and never emitted on its own.
	// The provider name is deliberately not a keyword here: prose like
	// "lambdatest API" would otherwise capture the word after it.
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"LT_USERNAME", "LAMBDATEST_USERNAME", "lambdatestUser",
		"userName", "USER_NAME", "username", "user",
	}) + `\b([a-zA-Z0-9][a-zA-Z0-9._-]{2,38})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lambdatest", "LT_ACCESS_KEY", "LT_AUTHKEY", "LT_USERNAME"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify LambdaTest secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[strings.TrimSpace(match[1])] = struct{}{}
	}

	uniqueUsers := make(map[string]struct{})
	for _, match := range userPat.FindAllStringSubmatch(dataStr, -1) {
		user := strings.TrimSpace(match[1])
		// The username pattern can pick up the start of an LT_ key itself;
		// those are not usernames.
		if strings.HasPrefix(user, "LT_") {
			continue
		}
		uniqueUsers[user] = struct{}{}
	}

	for key := range uniqueKeys {
		// A key with no username candidate cannot be verified and is useless
		// on its own, so it produces no result.
		for user := range uniqueUsers {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_LambdaTest,
				Raw:          []byte(key),
				RawV2:        []byte(key + user),
				SecretParts: map[string]string{
					"key":      key,
					"username": user,
				},
			}

			if verify {
				isVerified, verificationErr := verifyMatch(ctx, s.getClient(), user, key)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, username, token string) (bool, error) {
	payload, err := json.Marshal(map[string]string{"username": username, "token": token})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, lambdatestAuthURL, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", common.UserAgent())

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// The token auth endpoint returns 200 only for a valid username/key pair.
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_LambdaTest
}

func (s Scanner) Description() string {
	return "LambdaTest is a cloud testing platform providing cross-browser and device automation grids. LambdaTest access keys can be used to run and manage automated tests on the platform."
}
