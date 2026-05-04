package grafanaserviceaccount

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
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Pattern: glsa_ + 32 alphanumeric chars + _ + 8 hex chars = total 46 chars
	keyPat    = regexp.MustCompile(`\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b`)
	domainPat = regexp.MustCompile(`\b([a-zA-Z0-9-]+\.grafana\.net)\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"glsa_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify GrafanaServiceAccount secrets in a given set of bytes.
// If a grafana.net domain is found in the same chunk it is used for verification.
// If no domain is found the token is still emitted (unverified) so it is not silently dropped.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys = make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[strings.TrimSpace(match[1])] = struct{}{}
	}

	var uniqueDomains = make(map[string]struct{})
	for _, match := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[strings.TrimSpace(match[1])] = struct{}{}
	}

	for key := range uniqueKeys {
		if len(uniqueDomains) == 0 {
			// No domain found in this chunk — emit unverified so the token is not silently dropped.
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_GrafanaServiceAccount,
				Raw:          []byte(key),
				SecretParts:  map[string]string{"key": key},
			}
			results = append(results, s1)
			continue
		}

		for domain := range uniqueDomains {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_GrafanaServiceAccount,
				Raw:          []byte(key),
				RawV2:        []byte(domain + ":" + key),
				SecretParts: map[string]string{
					"key":    key,
					"domain": domain,
				},
			}

			if verify {
				isVerified, verificationErr := verifyGrafanaServiceAccount(ctx, s.getClient(), domain, key)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyGrafanaServiceAccount(ctx context.Context, client *http.Client, domain, key string) (bool, error) {
	// https://grafana.com/docs/grafana/latest/developers/http_api/access_control/
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/api/access-control/user/permissions", http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GrafanaServiceAccount
}

func (s Scanner) Description() string {
	return "Grafana service accounts are used to authenticate and interact with Grafana's API. These credentials can be used to access and modify Grafana resources and settings."
}
