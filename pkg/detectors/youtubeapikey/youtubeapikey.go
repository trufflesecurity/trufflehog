package youtubeapikey

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

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

	// YouTube API keys are typically 39 characters, alphanumeric with hyphens and underscores
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"youtube"}) + `\b([a-zA-Z0-9_-]{39})\b`)
	// Channel IDs are 24 characters, alphanumeric
	idPat = regexp.MustCompile(detectors.PrefixRegex([]string{"youtube"}) + `\b([a-zA-Z0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"youtube"}
}

// FromData will find and optionally verify YoutubeApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_YoutubeApiKey,
			Raw:          []byte(resMatch),
		}

		if verify {
			// Try verification with channel IDs if available
			var isVerified bool
			var verificationErr error

			if len(idmatches) > 0 {
				// Try with available channel IDs first
				for _, idmatch := range idmatches {
					resIdmatch := strings.TrimSpace(idmatch[1])
					isVerified, verificationErr = verifyWithChannelId(ctx, client, resMatch, resIdmatch)
					if isVerified {
						break
					}
				}
			}

			// If no channel IDs or verification failed, try simpler verification
			if !isVerified {
				isVerified, verificationErr = verifyApiKey(ctx, client, resMatch)
			}

			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyWithChannelId(ctx context.Context, client *http.Client, apiKey, channelId string) (bool, error) {
	// Reference: https://developers.google.com/youtube/v3/docs/channelSections/list
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://www.googleapis.com/youtube/v3/channelSections?key=%s&channelId=%s&part=snippet", apiKey, channelId),
		http.NoBody)
	if err != nil {
		return false, err
	}

	return executeRequest(client, req)
}

func verifyApiKey(ctx context.Context, client *http.Client, apiKey string) (bool, error) {
	// Use a simpler endpoint that doesn't require specific IDs
	// Reference: https://developers.google.com/youtube/v3/docs/i18nLanguages/list
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://www.googleapis.com/youtube/v3/i18nLanguages?key=%s&part=snippet", apiKey),
		http.NoBody)
	if err != nil {
		return false, err
	}

	return executeRequest(client, req)
}

func executeRequest(client *http.Client, req *http.Request) (bool, error) {
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK, http.StatusTooManyRequests:
		return true, nil
	case http.StatusBadRequest:
		return false, nil
	case http.StatusForbidden:
		body, _ := io.ReadAll(res.Body)
		if strings.Contains(string(body), "quotaExceeded") {
			return true, nil
		}
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_YoutubeApiKey
}

func (s Scanner) Description() string {
	return "YouTube API Keys allow access to various functionalities of the YouTube Data API, enabling operations such as retrieving video details and managing playlists."
}
