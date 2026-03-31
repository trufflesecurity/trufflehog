package persona

import (
	"context"
	"encoding/json"
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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(persona_(?:sandbox|production)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"persona_sandbox_", "persona_production_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keys := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, key := range keys {
		keyMatch := strings.TrimSpace(key[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Persona,
			Raw:          []byte(keyMatch),
			ExtraData:    make(map[string]string),
		}

		if strings.Contains(keyMatch, "_sandbox_") {
			s1.ExtraData["Type"] = "Sandbox Key"
		} else {
			s1.ExtraData["Type"] = "Production Key"
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, err := verifyPersonaKey(ctx, client, keyMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(err, keyMatch)

			if isVerified {
				for k, v := range extraData {
					s1.ExtraData[k] = v
				}
				s1.AnalysisInfo = map[string]string{"key": keyMatch}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyPersonaKey(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://withpersona.com/api/v1/api-keys/permissions", http.NoBody)
	if err != nil {
		return false, nil, nil
	}

	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Persona-Version", "2023-01-05")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		extraData := make(map[string]string)

		if orgID := res.Header.Get("Persona-Organization-Id"); orgID != "" {
			extraData["Organization"] = orgID
		}
		if envID := res.Header.Get("Persona-Environment-Id"); envID != "" {
			extraData["Environment"] = envID
		}

		body, err := io.ReadAll(res.Body)
		if err == nil {
			var resp apiKeyResponse
			if json.Unmarshal(body, &resp) == nil {
				if resp.Data.ID != "" {
					extraData["ID"] = resp.Data.ID
				}
				if resp.Data.Attributes.Name != "" {
					extraData["Name"] = resp.Data.Attributes.Name
				}
				if len(resp.Data.Attributes.Permissions) > 0 {
					extraData["Permissions"] = strings.Join(resp.Data.Attributes.Permissions, ", ")
				}
				if resp.Data.Attributes.ExpiresAt != "" {
					extraData["Expires_At"] = resp.Data.Attributes.ExpiresAt
				}
			}
		}

		return true, extraData, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil, nil

	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type apiKeyResponse struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
			ExpiresAt   string   `json:"expires_at"`
		} `json:"attributes"`
	} `json:"data"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Persona
}

func (s Scanner) Description() string {
	return "Persona is an identity verification platform. API keys can be used to access their identity verification and management services."
}
