package neon

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

var _ detectors.Detector = (*Scanner)(nil)

const (
	projectsURL    = "https://console.neon.tech/api/v2/projects"
	rotationGuide  = "https://neon.com/docs/manage/api-keys"
	maxProjectBody = 1 << 20
)

var (
	defaultClient = common.SaneHttpClient()

	// Newly created Neon API keys are prefixed with napi_ so scanners can find them.
	// https://neon.com/docs/changelog/2025-01-31
	keyPat = regexp.MustCompile(`\b(napi_[a-zA-Z0-9]{32,128})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"napi_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Neon,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
			ExtraData: map[string]string{
				"rotation_guide": rotationGuide,
			},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
			for k, v := range extraData {
				s1.ExtraData[k] = v
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, projectsURL, nil)
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
		extra := map[string]string{"scope": "account"}
		body, err := io.ReadAll(io.LimitReader(res.Body, maxProjectBody))
		if err != nil {
			return true, extra, nil
		}
		var payload struct {
			Projects []json.RawMessage `json:"projects"`
		}
		if json.Unmarshal(body, &payload) == nil {
			extra["project_count"] = fmt.Sprintf("%d", len(payload.Projects))
		}
		return true, extra, nil
	case http.StatusForbidden:
		// Project-scoped keys cannot list every project but are still live.
		return true, map[string]string{"scope": "project"}, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Neon
}

func (s Scanner) Description() string {
	return "Neon is a serverless Postgres platform. API keys authenticate to the Neon control plane and can list projects, reveal or reset database passwords, and create or delete branches."
}
