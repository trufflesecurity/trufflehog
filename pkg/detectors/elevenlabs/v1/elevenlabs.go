package elevenlabs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	lwa "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/lightweight_analyze"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

func (Scanner) Version() int { return 1 }

type UserRes struct {
	UserID       string `json:"user_id"`
	Subscription struct {
		Tier string `json:"tier"`
	} `json:"subscription"`
	FirstName string `json:"first_name"`
}

type ErrorRes struct {
	Detail struct {
		Status string `json:"status"`
	} `json:"detail"`
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
	logCtx := logContext.AddLogger(ctx)
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

			isVerified, extraData, verificationErr := verifyMatch(logCtx, client, match)
			s1.Verified = isVerified
			for k, v := range extraData {
				s1.ExtraData[k] = v
			}
			s1.SetVerificationError(verificationErr, match)

			if s1.Verified {
				s1.AnalysisInfo = map[string]string{
					"key": match,
				}
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx logContext.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.elevenlabs.io/v1/user", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("xi-api-key", token)
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}

	extraData := make(map[string]string)

	// lightweight analyze: unconditionally preserve the response body
	resBody := lwa.CopyAndCloseResponseBody(ctx, res)

	switch res.StatusCode {
	case http.StatusOK:
		// If the endpoint returns useful information, we can return it as a map.
		var userResponse UserRes
		if err = json.Unmarshal(resBody, &userResponse); err != nil {
			ctx.Logger().Error(err, "failed to parse response")
			return false, extraData, err
		}

		// lightweight analyze: annotate "standard" fields
		lwa.AugmentExtraData(extraData, lwa.Fields{
			ID:   &userResponse.UserID,
			Name: &userResponse.FirstName,
			// Could include subscription tier here if wanted
		})

		return true, extraData, nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		// If the response says {"detail":{"status":"missing_permissions","message":"The API key you used is missing the permission user_read to execute this operation."}}
		// then the key is valid, but we can't add the metadata
		var errorResponse ErrorRes
		if err = json.Unmarshal(resBody, &errorResponse); err != nil {
			ctx.Logger().Error(err, "failed to parse response")
			return false, extraData, err
		}
		if errorResponse.Detail.Status == "missing_permissions" {
			return true, extraData, nil
		}
		return false, extraData, nil
	default:
		return false, extraData, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ElevenLabs
}

func (s Scanner) Description() string {
	return "Elevenlabs is an AI-driven voice synthesis platform. Elevenlabs API keys can be used to access and manipulate voice synthesis features and services."
}
