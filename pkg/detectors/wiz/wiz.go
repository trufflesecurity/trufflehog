package wiz

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"wiz"}) + `\b([a-zA-Z0-9]{53})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"wiz"}) + `\b([a-zA-Z0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"wiz"}
}

// FromData will find and optionally verify Wiz secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := make(map[string]struct{})
	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[match[1]] = struct{}{}
	}

	secretMatches := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[match[1]] = struct{}{}
	}

	for idMatch := range idMatches {
		for secretMatch := range secretMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Wiz,
				Raw:          []byte(idMatch),
				RawV2:        []byte(idMatch + secretMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, client, idMatch, secretMatch)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, idMatch, secretMatch)
			}

			results = append(results, s1)

			// If we've found a verified match with this ID, we don't need to look for anymore. So move on to the next ID.
			if s1.Verified {
				break
			}
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, clientID, clientSecret string) (bool, map[string]string, error) {
	authData := url.Values{}
	authData.Set("grant_type", "client_credentials")
	authData.Set("audience", "wiz-api")
	authData.Set("client_id", clientID)
	authData.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://auth.app.wiz.io/oauth/token", strings.NewReader(authData.Encode()))
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Encoding", "UTF-8")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil, nil
	} else if res.StatusCode == 401 {
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	} else {
		err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
		return false, nil, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Wiz
}

func (s Scanner) Description() string {
	return "Wiz is a cloud security platform. Wiz credentials can be used to access and manage cloud security configurations."
}
