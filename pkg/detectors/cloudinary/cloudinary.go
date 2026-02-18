package cloudinary

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Cloudinary cloud names are typically b/w 3-50 characters.
	// This regex matches cloud names that appear near the word "cloudinary" and either the keyword "name" or "@" (as in URLs).
	cloudnamePat = regexp.MustCompile(`(?i:cloudinary)(?:.|[\n\r]){0,47}?` + `(?i:name|@)(?:.){0,10}?` + `\b([a-zA-Z][a-zA-Z0-9-]{2,49})\b`)

	// Cloudinary API keys are numeric and typically 15 digits long.
	apiKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudinary"}) + `\b(\d{15})\b`)

	// Cloudinary API secrets are typically 27 characters long and may contain
	// uppercase letters, lowercase letters, digits, underscores, or hyphens.
	apiSecretPat = regexp.MustCompile(`\b([A-Za-z0-9_-]{27})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cloudinary"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify DeepSeek secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueCloudNames := make(map[string]struct{})
	uniqueApiKeys := make(map[string]struct{})
	uniqueApiSecret := make(map[string]struct{})
	for _, match := range cloudnamePat.FindAllStringSubmatch(dataStr, -1) {
		uniqueCloudNames[match[1]] = struct{}{}
	}
	for _, match := range apiKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueApiKeys[match[1]] = struct{}{}
	}
	for _, match := range apiSecretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueApiSecret[match[1]] = struct{}{}
	}
	for cloudName := range uniqueCloudNames {
		for apiKey := range uniqueApiKeys {
			for apiSecret := range uniqueApiSecret {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Cloudinary,
					Raw:          []byte(apiKey),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", cloudName, apiKey, apiSecret)),
				}
				if verify {
					verified, verificationErr := verifyToken(ctx, s.getClient(), cloudName, apiKey, apiSecret)
					s1.SetVerificationError(verificationErr, cloudName, apiKey, apiSecret)
					s1.Verified = verified
				}
				results = append(results, s1)
			}
		}
	}
	return
}

func verifyToken(ctx context.Context, client *http.Client, cloudName, apiKey, apiSecret string) (bool, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   "api.cloudinary.com",
		Path:   path.Join("v1_1", cloudName, "usage"),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(apiKey, apiSecret)

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
		return true, nil
	case http.StatusUnauthorized:
		// Invalid
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Cloudinary
}

func (s Scanner) Description() string {
	return "Cloudinary is a cloud-based media management platform that provides image and video upload, storage, optimization, and delivery services via APIs and SDKs."
}
