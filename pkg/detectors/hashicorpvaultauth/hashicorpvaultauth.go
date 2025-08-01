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

	roleIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"role_id", "role-id", "roleid"}) + `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)

	secretIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret_id", "secret-id", "secretid"}) + `\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

	// Vault URL pattern - HashiCorp Cloud or any HTTPS/HTTP Vault endpoint
	vaultUrlPat = regexp.MustCompile(`https?:\/\/[^\s\/]*\.hashicorp\.cloud(?::\d+)?(?:\/[^\s]*)?`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"role_id", "secret_id", "vault", "approle", "hashicorp"}
}

// FromData will find and optionally verify HashiCorp Vault AppRole secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	roleIds := extractRoleIds(dataStr)
	secretIds := extractSecretIds(dataStr)
	vaultUrls := extractVaultUrls(dataStr)

	// If no names or secrets found, return empty results
	if len(roleIds) == 0 || len(secretIds) == 0 || len(vaultUrls) == 0 {
		return results, nil
	}

	// create combination results that can be verified
	for _, roleId := range roleIds {
		for _, secretId := range secretIds {
			for _, vaultUrl := range vaultUrls {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_HashiCorpVaultAuth,
					Raw:          []byte(secretId),
					RawV2:        []byte(fmt.Sprintf("role_id:%s,secret_id:%s,vault_url:%s", roleId, secretId, vaultUrl)),
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}

					isVerified, extraData, verificationErr := verifyMatch(ctx, client, roleId, secretId, vaultUrl)
					s1.Verified = isVerified
					s1.ExtraData = extraData
					if verificationErr != nil {
						s1.SetVerificationError(
							verificationErr,
							fmt.Sprintf("role_id:%s,secret_id:%s, url:%s",
								roleId, secretId, vaultUrl))
					}
				}
				results = append(results, s1)
			}
		}
	}
	return results, nil
}

// extractRoleIds finds all potential role_ids in the data
func extractRoleIds(data string) []string {
	var roleIds []string
	uniqueRoleIds := make(map[string]struct{})

	for _, match := range roleIdPat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			roleId := strings.TrimSpace(match[1])
			if _, exists := uniqueRoleIds[roleId]; !exists {
				uniqueRoleIds[roleId] = struct{}{}
				roleIds = append(roleIds, roleId)
			}
		}
	}
	return roleIds
}

// extractSecretIds finds all potential secret_ids in the data
func extractSecretIds(data string) []string {
	var secretIds []string
	uniqueSecretIds := make(map[string]struct{})

	for _, match := range secretIdPat.FindAllStringSubmatch(data, -1) {
		if len(match) >= 2 {
			secretId := strings.TrimSpace(match[1])
			if _, exists := uniqueSecretIds[secretId]; !exists {
				uniqueSecretIds[secretId] = struct{}{}
				secretIds = append(secretIds, secretId)
			}
		}
	}
	return secretIds
}

// extractVaultUrls finds all potential Vault URLs in the data
func extractVaultUrls(data string) []string {
	var urls []string
	uniqueUrls := make(map[string]struct{})

	for _, match := range vaultUrlPat.FindAllString(data, -1) {
		url := strings.TrimSpace(match)
		if _, exists := uniqueUrls[url]; !exists {
			uniqueUrls[url] = struct{}{}
			urls = append(urls, url)
		}
	}
	return urls
}

func verifyMatch(ctx context.Context, client *http.Client, roleId, secretId, vaultUrl string) (bool, map[string]string, error) {
	payload := map[string]string{
		"role_id":   roleId,
		"secret_id": secretId,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, nil, err
	}

	// Construct the AppRole login endpoint from the base Vault URL
	loginEndpoint := strings.TrimSuffix(vaultUrl, "/") + "/v1/auth/approle/login"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginEndpoint, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Namespace", "admin")

	res, err := client.Do(req)
	if err != nil {
		return false, map[string]string{"endpoint": loginEndpoint}, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	extraData := map[string]string{"endpoint": loginEndpoint}

	switch res.StatusCode {
	case http.StatusOK:
		return true, extraData, nil
	case http.StatusBadRequest:
		return false, extraData, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, extraData, nil
	case http.StatusNotFound:
		return false, extraData, nil
	default:
		extraData["error"] = fmt.Sprintf("unexpected_status_%d", res.StatusCode)
		return false, extraData, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_HashiCorpVaultAuth
}

func (s Scanner) Description() string {
	return "HashiCorp Vault AppRole authentication method uses role_id and secret_id for machine-to-machine authentication. These credentials can be used to authenticate with Vault and obtain tokens for accessing secrets."
}
