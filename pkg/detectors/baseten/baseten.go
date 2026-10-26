package baseten

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

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(b10_[A-Za-z0-9]{8}\.[A-Za-z0-9]{32})\b`)
)

type userInfo struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	WorkspaceName string `json:"workspace_name"`
}

func (s Scanner) Keywords() []string {
	return []string{"b10_"}
}

// FromData will find and optionally verify Baseten secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Baseten,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"rotation_guide": "https://docs.baseten.co/reference/management-api/api-keys/delete-an-api-key",
			},
			SecretParts: map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			for k, v := range extraData {
				s1.ExtraData[k] = v
			}
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// Returns 401 for invalid or revoked keys and 403 for valid keys lacking permission (as of 2026-10-28).
	// https://docs.baseten.co/reference/management-api/overview
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.baseten.co/v1/users/me", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

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
		var user userInfo
		if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
			return true, nil, nil
		}
		extraData := map[string]string{
			"user_id":        user.UserID,
			"email":          user.Email,
			"name":           user.Name,
			"workspace_name": user.WorkspaceName,
		}
		for k, v := range extraData {
			if v == "" {
				delete(extraData, k)
			}
		}
		return true, extraData, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Baseten
}

func (s Scanner) Description() string {
	return "Baseten is a platform for deploying and serving machine learning models. Baseten API keys grant access to model inference and the management API for a user or workspace."
}
