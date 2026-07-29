package vaulttoken

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
	detectors.EndpointSetter
}

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Recovery tokens are not covered by existing HashiCorpVaultToken/BatchToken detectors.
	tokenPat    = regexp.MustCompile(`\b(hvr\.[A-Za-z0-9_-]{100,})(?:$|[^A-Za-z0-9_-])`)
	vaultURLPat = regexp.MustCompile(`(https?:\/\/[^\s\/]*\.hashicorp\.cloud(?::\d+)?)(?:\/[^\s]*)?`)
)

func (s Scanner) Keywords() []string {
	return []string{"hvr.", "vault"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	uniqueVaultURLs := make(map[string]struct{})
	for _, match := range vaultURLPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueVaultURLs[strings.TrimSpace(match[1])] = struct{}{}
	}
	endpoints := make([]string, 0, len(uniqueVaultURLs))
	for endpoint := range uniqueVaultURLs {
		endpoints = append(endpoints, endpoint)
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

			vaultURLs := s.Endpoints(endpoints...)
			isVerified, verificationErr := verifyVaultToken(ctx, client, vaultURLs, token)
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
	if len(vaultUrls) == 0 {
		return false, fmt.Errorf("no vault endpoint found for verification")
	}

	var lastErr error
	for _, baseURL := range vaultUrls {
		verified, _, err := hashicorpvault.VerifyVaultToken(
			ctx,
			client,
			detector_typepb.DetectorType_VaultToken,
			baseURL,
			token,
		)
		if err != nil {
			lastErr = err
			continue
		}
		if verified {
			return true, nil
		}
	}

	if lastErr != nil {
		return false, lastErr
	}
	return false, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_VaultToken
}

func (s Scanner) Description() string {
	return "HashiCorp Vault tokens are used to authenticate with Vault servers. These tokens can be used to access secrets, manage policies, and perform administrative operations."
}
