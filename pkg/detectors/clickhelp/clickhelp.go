package clickhelp

import (
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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	portalPat = regexp.MustCompile(`\b([0-9A-Za-z-]{3,20}\.(?:try\.)?clickhelp\.co)\b`)
	emailPat  = regexp.MustCompile(common.EmailPattern)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"clickhelp", "key", "token", "api", "secret"}) + `\b([0-9A-Za-z]{24})\b`)
)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ClickHelp
}

func (s Scanner) Description() string {
	return "ClickHelp is a documentation tool that allows users to create and manage online documentation. ClickHelp API keys can be used to access and modify documentation data."
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"clickhelp.co"}
}

// FromData will find and optionally verify Clickhelp secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniquePortalLinks, uniqueEmails, uniqueAPIKeys = make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, match := range portalPat.FindAllStringSubmatch(dataStr, -1) {
		uniquePortalLinks[match[1]] = struct{}{}
	}

	for _, match := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmails[match[1]] = struct{}{}
	}

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPIKeys[match[1]] = struct{}{}
	}

	for portalLink := range uniquePortalLinks {
		for email := range uniqueEmails {
			for apiKey := range uniqueAPIKeys {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ClickHelp,
					Raw:          []byte(portalLink),
					RawV2:        []byte(portalLink + email),
				}

				if verify {
					isVerified, verificationErr := verifyClickHelp(ctx, client, portalLink, email, apiKey)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr)
					s1.SetPrimarySecretValue(apiKey) // line number will point to api key
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func verifyClickHelp(ctx context.Context, client *http.Client, portalLink, email, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/api/v1/projects", portalLink), http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(email, apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
