package rancher

import (
	"context"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	// Match known Rancher/Cattle variable names followed by the token value.
	// (?i:...) scopes case-insensitivity to the variable name only; the capture
	// group stays case-sensitive because Rancher tokens are lowercase alphanumeric.
	keyPat = regexp.MustCompile(
		`(?i:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN|RANCHER_SECRET_KEY)` +
			`\s*[=:]\s*["']?([a-z0-9]{54,64}\b)["']?`)
)

func (s Scanner) Keywords() []string {
	return []string{"cattle_token", "cattle_bootstrap_password", "rancher_token", "rancher_api_token", "rancher_secret_key"}
}

// FromData finds and optionally verifies Rancher API tokens in a chunk of data.
// Verification is not supported without a live CATTLE_SERVER URL; matched tokens
// are returned as unverified (Verified=false, no VerificationError).
func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})

	var results []detectors.Result
	for _, m := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		token := m[1]
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}

		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_Rancher,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"token": token},
		})
	}

	return results, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Rancher
}

func (s Scanner) Description() string {
	return "Rancher is a Kubernetes management platform used by 37,000+ organizations. " +
		"Rancher API tokens provide full cluster admin access and must be treated as critical secrets."
}
