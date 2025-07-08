package airbrakeprojectkey

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"airbrake"}) + `\b([a-zA-Z-0-9]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"airbrake"}) + `\b([0-9]{6})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"airbrake"}
}

// FromData will find and optionally verify AirbrakeProjectKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys, uniqueIds = make(map[string]struct{}), make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueIds[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		for id := range uniqueIds {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_AirbrakeProjectKey,
				Raw:          []byte(key),
				RawV2:        []byte(key + id),
			}
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/airbrake/",
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyAirbrakeProjectKey(ctx, client, key, id)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)

		}

	}

	return results, nil
}

func verifyAirbrakeProjectKey(ctx context.Context, client *http.Client, key string, id string) (bool, error) {
	url := "https://api.airbrake.io/api/v4/projects/" + id + "/deploys?key=" + key
	payload := strings.NewReader(`{"environment":"production","username":"john","email":"john@smith.com","repository":"https://github.com/airbrake/airbrake","revision":"38748467ea579e7ae64f7815452307c9d05e05c5","version":"v2.0"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// handle according to detector API responses.
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AirbrakeProjectKey
}

func (s Scanner) Description() string {
	return "Airbrake is an error and performance monitoring service for web applications. Airbrake project keys can be used to report and track errors in applications."
}
