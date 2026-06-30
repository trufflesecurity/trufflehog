package vaulttoken

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// HashiCorp Vault token patterns
	// Service tokens (Vault 1.10+): hvs.CAESXXXX... (90+ chars)
	// Batch tokens: hvb.AAAAAQXXXX... (138+ chars)
	// Recovery tokens: hvr.CAESXXXX... (138+ chars)
	// Legacy service tokens: s.XXXXXXXX... (24+ chars)
	tokenPat = regexp.MustCompile(`\b(hvs\.[A-Za-z0-9_-]{20,}|hvb\.[A-Za-z0-9_-]{100,}|hvr\.[A-Za-z0-9_-]{100,}|s\.[a-zA-Z0-9]{24,})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"hvs.", "hvb.", "hvr.", "vault_token", "VAULT_TOKEN"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_VaultToken,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			// Try to get Vault server URL from endpoints or use common defaults
			vaultUrls := s.Endpoints("https://vault.example.com")
			if len(vaultUrls) == 0 {
				vaultUrls = []string{
					"http://127.0.0.1:8200",
					"http://localhost:8200",
					"https://vault.hashicorp.cloud",
				}
			}

			isVerified, verificationErr := verifyVaultToken(ctx, client, vaultUrls, token)
			s1.Verified = isVerified

			if verificationErr != nil {
				s1.SetVerificationError(verificationErr, token)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyVaultToken(ctx context.Context, client *http.Client, vaultUrls []string, token string) (bool, error) {
	for _, baseURL := range vaultUrls {
		// Use token lookup-self endpoint to verify token
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/auth/token/lookup-self", nil)
		if err != nil {
			continue
		}

		req.Header.Set("X-Vault-Token", token)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// Token is valid - parse response to confirm
			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
				if _, ok := result["data"]; ok {
					return true, nil
				}
			}
			return true, nil
		case http.StatusForbidden, http.StatusUnauthorized:
			// 403/401 - Invalid or expired token
			return false, nil
		case http.StatusBadRequest:
			// 400 - Malformed request, continue to next URL
			continue
		default:
			// Try next URL
			continue
		}
	}

	// Could not verify with any URL - return error
	return false, fmt.Errorf("unable to verify token with provided Vault endpoints")
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_VaultToken
}

func (s Scanner) Description() string {
	return "HashiCorp Vault tokens are used to authenticate with Vault servers. These tokens can be used to access secrets, manage policies, and perform administrative operations."
}
