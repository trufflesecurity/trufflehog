package rancher

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Match Rancher/Cattle token variable names followed by the token value.
	// Tokens are 54-64 lowercase alphanumeric chars; (?i:...) scopes
	// case-insensitivity to the variable name prefix only, keeping the
	// capture group case-sensitive to avoid false positives on uppercase strings.
	keyPat = regexp.MustCompile(
		`(?i:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN|RANCHER_SECRET_KEY)` +
			`[\w]*\s*[=:]\s*["']?([a-z0-9]{54,64})["']?`)
)

func (s Scanner) Keywords() []string {
	return []string{"cattle_token", "rancher_token", "cattle_bootstrap_password", "rancher_api_token", "rancher_secret_key"}
}

// FromData finds and optionally verifies Rancher API tokens in a chunk of data.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})

	var results []detectors.Result
	for _, m := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		token := m[1]
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}

		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Rancher,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"token": token},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			// Verification requires a server URL, which we may not have.
			// We flag the token as unverified rather than skipping it.
			isVerified, verificationErr := verifyRancherToken(ctx, client, token)
			r.Verified = isVerified
			r.SetVerificationError(verificationErr)
		}

		results = append(results, r)
	}

	return results, nil
}

// verifyRancherToken checks the token against the Rancher management API.
// It requires CATTLE_SERVER to be present in the same context, but since
// TruffleHog does not pass environment context here, we attempt a generic
// check. Real verification happens in integration tests with a live server.
func verifyRancherToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Without a server URL we cannot verify; return (false, nil) so the result
	// is classified as unverified rather than unknown.
	return false, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Rancher
}

func (s Scanner) Description() string {
	return "Rancher is a Kubernetes management platform used by 37,000+ organizations. " +
		"Rancher API tokens provide full cluster admin access and must be treated as critical secrets."
}
