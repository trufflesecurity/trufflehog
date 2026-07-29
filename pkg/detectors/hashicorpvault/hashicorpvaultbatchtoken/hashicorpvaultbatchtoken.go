package hashicorpbatchtoken

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/hashicorpvault"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

var (
	defaultClient = detectors.NewClientWithDedup(detectors.DetectorHttpClientWithNoLocalAddresses)

	// Batch tokens: hvb.<50-300 chars>
	batchTokenPat = regexp.MustCompile(
		`\b(hvb\.[A-Za-z0-9_.-]{50,300})(?:[^A-Za-z0-9_.-]|\z)`,
	)

	vaultUrlPat = regexp.MustCompile(`(https?:\/\/[^\s\/]*\.hashicorp\.cloud(?::\d+)?)(?:\/[^\s]*)?`)
)

func (s Scanner) Keywords() []string {
	return []string{"hvb."}
}

func (Scanner) CloudEndpoint() string { return "" }

func (s Scanner) Description() string {
	return "This detector detects and verifies HashiCorp Vault batch tokens"
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueTokens := make(map[string]struct{})
	for _, match := range batchTokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[match[1]] = struct{}{}
	}

	var uniqueVaultUrls = make(map[string]struct{})
	for _, match := range vaultUrlPat.FindAllStringSubmatch(dataStr, -1) {
		url := strings.TrimSpace(match[1])
		uniqueVaultUrls[url] = struct{}{}
	}

	endpoints := make([]string, 0, len(uniqueVaultUrls))
	for endpoint := range uniqueVaultUrls {
		endpoints = append(endpoints, endpoint)
	}

	for _, endpoint := range s.Endpoints(endpoints...) {
		for token := range uniqueTokens {
			result := detectors.Result{
				DetectorType: detector_typepb.DetectorType_HashiCorpVaultBatchToken,
				Raw:          []byte(token),
				RawV2:        []byte(token + ":" + endpoint),
				Redacted:     token[:8] + "...",
				SecretParts: map[string]string{
					"key": token,
					"url": endpoint,
				},
			}

			if verify {
				verified, verificationResp, verificationErr := hashicorpvault.VerifyVaultToken(
					ctx,
					s.getClient(),
					s.Type(),
					endpoint,
					token,
				)
				result.SetVerificationError(verificationErr, token)
				result.Verified = verified

				if verificationResp != nil {
					result.ExtraData = map[string]string{
						"orphan":    fmt.Sprintf("%v", verificationResp.Data.Orphan),
						"renewable": fmt.Sprintf("%v", verificationResp.Data.Renewable),
						"type":      verificationResp.Data.Type,
						"entity_id": verificationResp.Data.EntityId,
					}
					result.ExtraData["policies"] = strings.Join(verificationResp.Data.Policies, ", ")
				}
			}

			results = append(results, result)
		}
	}

	return
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_HashiCorpVaultBatchToken
}
