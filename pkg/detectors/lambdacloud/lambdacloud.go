package lambdacloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const verifyURL = "https://cloud.lambda.ai/api/v1/identity"

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat = regexp.MustCompile(`\b(secret_[a-z0-9][a-z0-9-]{0,63}_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\.[A-Za-z0-9]{32})(?:[^A-Za-z0-9]|$)`)
)

func (s Scanner) Keywords() []string {
	return []string{"secret_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	seen := make(map[string]struct{})
	for _, match := range keyPat.FindAllSubmatchIndex(data, -1) {
		token := string(data[match[2]:match[3]])
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}

		result := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			verified, extraData, verificationErr := verifyToken(ctx, client, token)
			result.Verified = verified
			result.ExtraData = extraData
			result.SetVerificationError(verificationErr, token)
		}
		results = append(results, result)
	}
	return results, nil
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

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
		var response struct {
			Data identityResponse `json:"data"`
		}
		if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
			return false, nil, err
		}
		if response.Data.ID == "" || response.Data.AccountID == "" {
			return false, nil, fmt.Errorf("unexpected Lambda Cloud identity response")
		}

		extraData := map[string]string{
			"identity_id": response.Data.ID,
			"account_id":  response.Data.AccountID,
		}
		if response.Data.IdentityType != "" {
			extraData["identity_type"] = response.Data.IdentityType
		}
		if response.Data.Email != "" {
			extraData["email"] = response.Data.Email
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_LambdaCloud
}

func (s Scanner) Description() string {
	return "Lambda Cloud provides GPU computing infrastructure. Lambda Cloud API keys can be used to manage instances, filesystems, SSH keys, and other cloud resources."
}

type identityResponse struct {
	ID           string `json:"id"`
	AccountID    string `json:"account_id"`
	IdentityType string `json:"identity_type"`
	Email        string `json:"email"`
}
