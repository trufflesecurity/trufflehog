package ranchertoken

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	// Token pattern: 54-64 char lowercase alphanumeric, only when near context keywords.
	tokenPat = regexp.MustCompile(`(?:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN|RANCHER_SECRET_KEY)[\w]*\s*[=:]\s*["']?([a-z0-9]{54,64})["']?`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"cattle_token", "rancher_token", "cattle_bootstrap_password", "rancher_api_token", "rancher_secret_key"}
}

// FromData will find and optionally verify Rancher/Cattle tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := tokenPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_RancherToken,
			Raw:          []byte(resMatch),
		}

		// Verification is not possible for Rancher tokens since we cannot
		// determine the Rancher server URL from the token alone.

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_RancherToken
}

func (s Scanner) Description() string {
	return "Rancher is a Kubernetes management platform. Rancher API tokens (also known as Cattle tokens) provide full administrative access to Rancher-managed Kubernetes clusters."
}
