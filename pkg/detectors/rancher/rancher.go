package rancher

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	// Use the SSRF-safe client that blocks requests to local/private IP ranges.
	client = detectors.DetectorHttpClientWithNoLocalAddresses

	// Match variable name case-insensitively via (?i:...) scope, then require strictly
	// lowercase alphanumeric token to avoid false positives from the broad character set.
	keyPat = regexp.MustCompile(`(?i:(?:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN)[\w]*\s*[=:]\s*["']?)([a-z0-9]{54,64})["']?`)

	// Server URL used for validation; must appear nearby in the same chunk.
	serverPat = regexp.MustCompile(`(?i:(?:CATTLE_SERVER|RANCHER_URL|RANCHER_SERVER)\s*[=:]\s*["']?)(https?://[^\s"']+)["']?`)
)

func (s Scanner) Keywords() []string {
	return []string{"CATTLE_TOKEN", "RANCHER_TOKEN", "CATTLE_BOOTSTRAP_PASSWORD", "RANCHER_API_TOKEN"}
}

func verifyToken(ctx context.Context, serverURL, token string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", serverURL+"/v3", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = res.Body.Close() }()
	return res.StatusCode == http.StatusOK
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokenMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	serverMatches := serverPat.FindAllStringSubmatch(dataStr, -1)

	for _, tokenMatch := range tokenMatches {
		token := strings.TrimSpace(tokenMatch[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_RancherToken,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"token": token},
		}

		if verify && len(serverMatches) > 0 {
			serverURL := strings.TrimRight(strings.TrimSpace(serverMatches[0][1]), "/")
			s1.Verified = verifyToken(ctx, serverURL, token)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_RancherToken
}

func (s Scanner) Description() string {
	return "Rancher is a Kubernetes management platform. Rancher API tokens provide full cluster admin access and must be protected."
}
