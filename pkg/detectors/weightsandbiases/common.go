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
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

var DefaultClient = common.SaneHttpClient()

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

// VerifyWeightsAndBiases checks the credential against the W&B GraphQL /graphql endpoint using the
// viewer query, which requires no special permissions. A 200 with a non-empty username means the
// token is valid; 401 means invalid or revoked.
// Docs: https://docs.wandb.ai/ref/graphql
func VerifyWeightsAndBiases(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
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

// FromData finds and optionally verifies WeightsAndBiases secrets in data using the provided pattern.
func FromData(ctx context.Context, verify bool, client *http.Client, data []byte, keyPat *regexp.Regexp) ([]detectors.Result, error) {
	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(string(data), -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	var results []detectors.Result
	for match := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_WeightsAndBiases,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			isVerified, extraData, verificationErr := VerifyWeightsAndBiases(ctx, client, match)
			r.Verified = isVerified
			r.ExtraData = extraData
			r.SetVerificationError(verificationErr, match)
		}

		results = append(results, r)
	}
	return results, nil
}
