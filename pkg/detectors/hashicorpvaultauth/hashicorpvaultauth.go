package hashicorpvaultauth

import (
	"bytes"
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

	roleIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"role"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)

	secretIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret"}) + `\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

	// Vault URL pattern - HashiCorp Cloud or any HTTPS/HTTP Vault endpoint
	vaultUrlPat = regexp.MustCompile(`(https?:\/\/[^\s\/]*\.hashicorp\.cloud(?::\d+)?)(?:\/[^\s]*)?`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"hashicorp"}
}

// FromData will find and optionally verify HashiCorp Vault AppRole secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueRoleIds = make(map[string]struct{})
	for _, match := range roleIdPat.FindAllStringSubmatch(dataStr, -1) {
		roleId := strings.TrimSpace(match[1])
		uniqueRoleIds[roleId] = struct{}{}
	}

	var uniqueSecretIds = make(map[string]struct{})
	for _, match := range secretIdPat.FindAllStringSubmatch(dataStr, -1) {
		secretId := strings.TrimSpace(match[1])
		uniqueSecretIds[secretId] = struct{}{}
	}

	var uniqueVaultUrls = make(map[string]struct{})
	for _, match := range vaultUrlPat.FindAllString(dataStr, -1) {
		url := strings.TrimSpace(match)
		uniqueVaultUrls[url] = struct{}{}
	}

	// If no names or secrets found, return empty results
	if len(uniqueRoleIds) == 0 || len(uniqueSecretIds) == 0 || len(uniqueVaultUrls) == 0 {
		return results, nil
	}

	// create combination results that can be verified
	for roleId := range uniqueRoleIds {
		for secretId := range uniqueSecretIds {
			for vaultUrl := range uniqueVaultUrls {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_HashiCorpVaultAuth,
					Raw:          []byte(secretId),
					RawV2:        []byte(fmt.Sprintf("%s:%s", roleId, secretId)),
					ExtraData: map[string]string{
						"URL": vaultUrl,
					},
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}

					isVerified, verificationErr := verifyMatch(ctx, client, roleId, secretId, vaultUrl)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, roleId, secretId, vaultUrl)
				}
				results = append(results, s1)
			}
		}
	}
	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, roleId, secretId, vaultUrl string) (bool, error) {
	payload := map[string]string{
		"role_id":   roleId,
		"secret_id": secretId,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, vaultUrl+"/v1/auth/approle/login", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Namespace", "admin")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		if strings.Contains(string(body), "invalid role or secret ID") {
			return false, nil
		} else {
			return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
		}
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_HashiCorpVaultAuth
}

func (s Scanner) Description() string {
	return "HashiCorp Vault AppRole authentication method uses role_id and secret_id for machine-to-machine authentication. These credentials can be used to authenticate with Vault and obtain tokens for accessing secrets."
}
