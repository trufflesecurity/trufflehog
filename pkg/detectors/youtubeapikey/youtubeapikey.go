package youtubeapikey

import (
	"context"
	"fmt"
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

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"youtube"}) + `\b([a-zA-Z-0-9_]{39})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"youtube"}) + `\b([a-zA-Z-0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"youtube"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return client
}

// FromData will find and optionally verify YoutubeApiKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idmatches {
			resIdmatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_YoutubeApiKey,
				Raw:          []byte(resMatch),
				SecretParts:  map[string]string{"key": resMatch},
			}

			if verify {
				isVerified, verificationErr := verifyYoutubeAPIKey(ctx, s.getClient(), resMatch, resIdmatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func verifyYoutubeAPIKey(ctx context.Context, client *http.Client, key, channelID string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/youtube/v3/channelSections?key="+key+"&channelId="+channelID, nil)
	if err != nil {
		return false, err
	}
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_YoutubeApiKey
}

func (s Scanner) Description() string {
	return "YouTube API Keys allow access to various functionalities of the YouTube Data API, enabling operations such as retrieving video details and managing playlists."
}
