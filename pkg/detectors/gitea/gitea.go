package gitea

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
	_ detectors.CloudProvider      = (*Scanner)(nil)
)

func (Scanner) CloudEndpoint() string { return "https://gitea.com" }

var (
	defaultClient = common.SaneHttpClient()

	// Gitea API tokens are 40-character lowercase hexadecimal strings.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"gitea"}) + `\b([a-f0-9]{40})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gitea"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Gitea
}

func (s Scanner) Description() string {
	return "Gitea is a self-hosted, lightweight Git service. Gitea API tokens can be used to access and modify repositories, organizations, issues, and other resources."
}

// FromData will find and optionally verify Gitea secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for token := range uniqueMatches {
		for _, endpoint := range s.Endpoints() {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Gitea,
				Raw:          []byte(token),
				RawV2:        []byte(token + endpoint),
				SecretParts: map[string]string{
					"key": token,
				},
				ExtraData: map[string]string{
					"host": endpoint,
				},
			}

			if verify {
				isVerified, verificationErr := verifyGitea(ctx, s.getClient(), endpoint, token)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, token)

				// For verified keys break out of the endpoint loop to continue to the next secret.
				if s1.Verified {
					results = append(results, s1)
					break
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyGitea(ctx context.Context, client *http.Client, baseEndpoint, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseEndpoint+"/api/v1/user", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The token is determinately invalid (or revoked / lacking access).
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
