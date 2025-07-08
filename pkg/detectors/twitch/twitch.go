package twitch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

const verifyURL = "https://id.twitch.tv/oauth2/token"

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"twitch"}) + `\b([0-9a-z]{30})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"twitch"}) + `\b([0-9a-z]{30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"twitch"}
}

// FromData will find and optionally verify Twitch secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueIDMatches, uniqueSecretMatches = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIDMatches[match[1]] = struct{}{}
	}

	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecretMatches[match[1]] = struct{}{}
	}

	for id := range uniqueIDMatches {
		for secret := range uniqueSecretMatches {
			// as both patterns are same, to avoid same strings
			if id == secret {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Twitch,
				Raw:          []byte(id),
				RawV2:        []byte(id + ":" + secret),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyTwitch(ctx, client, secret, id)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, id)
			}

			results = append(results, s1)
		}
	}
	return results, nil
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func verifyTwitch(ctx context.Context, client *http.Client, resMatch string, resIdMatch string) (bool, error) {
	data := url.Values{}
	data.Set("client_id", resIdMatch)
	data.Set("client_secret", resMatch)
	data.Set("grant_type", "client_credentials")
	encodedData := data.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(encodedData))
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected http response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Twitch
}

func (s Scanner) Description() string {
	return "Twitch is a live streaming service. Twitch client credentials can be used to access and modify data on the Twitch platform."
}
