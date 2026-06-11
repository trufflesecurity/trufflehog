package user

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.NewClientWithDedup(detectors.DetectorHttpClientWithNoLocalAddresses)

	keyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"user"}) + `\b([A-Za-z0-9]{64})\b`)
	userURLPat = regexp.MustCompile(`\b([a-z0-9-]+\.user\.com)\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"user"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify User secrets in a given set of bytes.
// Both an API key and a subdomain URL (e.g. https://acme.user.com) must be present
// for a result to be reported, since each account has its own endpoint.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[strings.TrimSpace(match[1])] = struct{}{}
	}

	uniqueURLs := make(map[string]struct{})
	for _, match := range userURLPat.FindAllStringSubmatch(dataStr, -1) {
		u := url.URL{Scheme: "https", Host: match[1]}
		uniqueURLs[u.String()] = struct{}{}
	}

	// Require both parts of the credential to be present.
	if len(uniqueTokens) == 0 || len(uniqueURLs) == 0 {
		return
	}

	for token := range uniqueTokens {
		for baseURL := range uniqueURLs {
			result := detectors.Result{
				DetectorType: detector_typepb.DetectorType_User,
				Raw:          []byte(token),
				RawV2:        []byte(token + ":" + baseURL),
				SecretParts: map[string]string{
					"key":      token,
					"endpoint": baseURL,
				},
			}

			if verify {
				isVerified, verificationErr := verifyUserToken(ctx, s.getClient(), token, baseURL)
				result.Verified = isVerified
				result.SetVerificationError(verificationErr, token)
			}

			results = append(results, result)
		}
	}

	return
}

func verifyUserToken(ctx context.Context, client *http.Client, token, baseURL string) (bool, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false, err
	}
	u.Path = "/api/public/users/"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		u.String(),
		http.NoBody,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Token %s", token))

	res, err := detectors.DoWithDedup(client, detector_typepb.DetectorType_User, token+":"+baseURL, req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusGone:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_User
}

func (s Scanner) Description() string {
	return "User credentials can be used to authenticate and authorize actions within the User service, potentially allowing access to sensitive data and operations."
}
