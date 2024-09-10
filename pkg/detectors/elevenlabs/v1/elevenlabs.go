package elevenlabs

import (
	"context"
	"encoding/json"
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

func (Scanner) Version() int { return 1 }

type UserRes struct {
	Subscription struct {
		Tier string `json:"tier"`
	} `json:"subscription"`
	Name string `json:"first_name"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`(?i)(?:elevenlabs|xi-api-key|el|token|key)[^\.].{0,40}[ =:'"]+([a-f0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"elevenlabs", "xi-api-key", "xi_api_key"}
}

// FromData will find and optionally verify Elevenlabs secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_ElevenLabs,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"version":        "1",
				"rotation_guide": "https://howtorotate.com/docs/tutorials/elevenlabs/",
			},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, userResponse, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			if userResponse != nil {
				s1.ExtraData["Name"] = userResponse.Name
				s1.ExtraData["Tier"] = userResponse.Subscription.Tier
			}
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, *UserRes, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.elevenlabs.io/v1/user", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("xi-api-key", token)
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// If the endpoint returns useful information, we can return it as a map.
		var userResponse UserRes
		if err = json.NewDecoder(res.Body).Decode(&userResponse); err != nil {
			return false, nil, err
		}
		return true, &userResponse, nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ElevenLabs
}
