package smartling

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.

	// TODO: These regexes are not guaranteed to be correct as we don't have access to a smartling account yet
	// These are our best guesses based on publicly available information.
	//
	// We have screenshots containing the User identifier and secret in guides in Smartling's official documentation, as well as other third party documentations:
	// - https://help.smartling.com/hc/en-us/articles/360009611313-AEM-Touch-Connector-Configuration-5-0x#:~:text=the%20AEM%20locale%20as%20the%20source%20locale.
	// - https://help.smartling.com/hc/en-us/articles/360008158133-WordPress-Connector-Installation-Setup#:~:text=Click%20Account%20Settings%20%3E%20API%20%3E%20v%202.0
	// - https://help.smartling.com/hc/en-us/articles/360007935194-AEM-Classic-Connector-Installation-and-Configuration#:~:text=In%20the%20General%20Settings%20tab
	// - https://docs.blackbird.io/apps/smartling/#:~:text=Smartling%20via%20Blackbird.-,Connecting,-Navigate%20to%20apps

	userIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"smartling", "user", "id"}) + `\b([a-z]{30})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"smartling", "secret", "key"}) + `\b([A-Za-z0-9._^-]{55})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"smartling"}
}

// FromData will find and optionally verify Smartling secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatchesUserId := make(map[string]struct{})
	for _, match := range userIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatchesUserId[match[1]] = struct{}{}
	}
	uniqueMatchesSecret := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatchesSecret[match[1]] = struct{}{}
	}

	for userId := range uniqueMatchesUserId {
		for secret := range uniqueMatchesSecret {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Smartling,
				Raw:          []byte(userId),
				RawV2:        []byte(fmt.Sprintf("%s:%s", userId, secret)),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, userId, secret)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, userId, secret)
				s1.SetPrimarySecretValue(secret)
			}

			results = append(results, s1)
		}

	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, userId string, secret string) (bool, error) {
	body := []byte(fmt.Sprintf(`{"userIdentifier":"%s","userSecret":"%s"}`, userId, secret))

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "https://api.smartling.com/auth-api/v2/authenticate", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

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
		// The secret is verified
		return true, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Smartling
}

func (s Scanner) Description() string {
	return "Smartling is a cloud-based translation technology and language services company headquartered in New York City."
}
