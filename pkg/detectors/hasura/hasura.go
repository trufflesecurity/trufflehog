package hasura

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

	// domainPat finds Hasura cloud domains.
	domainPat = regexp.MustCompile(`\b([a-zA-Z0-9-]+\.hasura\.app)\b`)
	// keyPat finds potential Hasura admin secrets, often prefixed with "hasura".
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hasura"}) + `\b([a-zA-Z0-9]{64})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"hasura"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// FromData will find and optionally verify Hasura secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeyMatches, uniqueDomainMatches = make(map[string]struct{}), make(map[string]struct{})

	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyMatches[match[1]] = struct{}{}
	}

	for _, match := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomainMatches[match[1]] = struct{}{}
	}

	// Logic: For each key, try to verify against each found domain.
	// Stop and record a verified finding on the first successful match.
	for key := range uniqueKeyMatches {
		for domain := range uniqueDomainMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Hasura,
				Raw:          []byte(key),
				RawV2:        fmt.Appendf([]byte(""), "%s:%s", domain, key),
			}

			if verify {
				isVerified, extraData, verificationErr := s.verifyHasura(ctx, s.getClient(), domain, key)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
			// If we successfully verified this key with a domain, we don't need to check it against other domains.
			if s1.Verified {
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Hasura
}

func (s Scanner) Description() string {
	return `Hasura is an open-source engine that instantly generates GraphQL and REST APIs over PostgreSQL (and other databases). 
	It allows you to query, mutate, and subscribe to data in real time. Admin secrets (or admin keys) are used to securely access
	and manage Hasura projects, giving full control over data, metadata, and schema.`
}

// verifyHasura attempts to validate a Hasura key against a given domain.
func (s Scanner) verifyHasura(ctx context.Context, client *http.Client, domain, key string) (bool, map[string]string, error) {
	query := `{"query":"query { __schema { types { name } } }"}`
	url := fmt.Sprintf("https://%s/v1/graphql", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(query))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-hasura-admin-secret", key)

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	extraData := map[string]string{"domain": domain}

	// Since the API returns 200 OK for both valid and invalid keys, we MUST parse the body.
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, extraData, err
	}

	// Handle non-200 status codes
	if resp.StatusCode != http.StatusOK {
		// Special case: Project not reachable is a definitive "not verified", not an error
		if resp.StatusCode == http.StatusInternalServerError && isHasuraProjectUnavailable(bodyBytes) {
			return false, extraData, nil
		}
		return false, extraData, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var response struct {
		Data   any   `json:"data"`
		Errors []any `json:"errors"`
	}

	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return false, extraData, fmt.Errorf("failed to unmarshal json response: %w", err)
	}

	// Key is verified if we have data and no errors
	if response.Data != nil && len(response.Errors) == 0 {
		return true, extraData, nil
	}

	// Key is not verified if we have errors or no data
	return false, extraData, nil
}

func isHasuraProjectUnavailable(bodyBytes []byte) bool {
	return bytes.Contains(bodyBytes, []byte("Project not reachable")) || bytes.Contains(bodyBytes, []byte("Unable to load this project"))
}
