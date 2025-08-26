package weightsandbiases

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{ client *http.Client }

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"wandb"}) + `\b([0-9a-f]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string { return []string{"wandb"} }

// FromData will find and optionally verify Weightsandbiases secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_WeightsAndBiases,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

type viewerResponse struct {
	Data struct {
		Viewer struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Admin    bool   `json:"admin"`
		} `json:"viewer"`
	} `json:"data"`
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	query := `{"query": "query Viewer { viewer { id username email admin } }"}`

	const baseURL = "https://api.wandb.ai/graphql"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewBufferString(query))
	if err != nil {
		return false, nil, err
	}

	authHeader := base64.StdEncoding.EncodeToString([]byte("api:" + token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+authHeader)

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
		var viewerResp viewerResponse
		if err := json.NewDecoder(res.Body).Decode(&viewerResp); err != nil {
			return false, nil, err
		}

		// Only consider it verified if we got back a username.
		if viewerResp.Data.Viewer.Username == "" {
			return false, nil, nil
		}

		extraData := map[string]string{
			"username": viewerResp.Data.Viewer.Username,
			"email":    viewerResp.Data.Viewer.Email,
			"admin":    strconv.FormatBool(viewerResp.Data.Viewer.Admin),
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Description() string {
	return "Weights & Biases is a Machine Learning Operations (MLOps) platform that helps track experiments, version datasets, evaluate model performance, and collaborate with team members"
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_WeightsAndBiases
}
