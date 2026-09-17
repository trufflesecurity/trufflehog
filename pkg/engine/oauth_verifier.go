// oauth_verifier.go adapts the engine's per-detector OAuth2 config into
// the shared VerifyCredential loop. The engine scan loop calls OAuthVerify
// when a detector has a custom verifier with OAuth2 auth configured.
//
// All core verification logic (body template resolution, header
// application, OAuth client wrapping, status code interpretation,
// endpoint fallback, response capture, outcome logging) lives in the
// shared VerifyCredential function in pkg/custom_detectors/verify.go.

package engine

import (
	"context"
	"fmt"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	custom_detectors "github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

var defaultOAuthBaseClient = common.SaneHttpClient()

// OAuthVerifyConfig holds the per-endpoint settings the engine needs
// to perform OAuth2-authenticated verification. It mirrors the
// relevant fields from VerifierConfig without importing the proto
// directly into the detectors package.
type OAuthVerifyConfig struct {
	Endpoint      string
	SuccessRanges []string
	RotatedRanges []string
	// RequestBody is the customer-defined body template with $token
	// references. Nil means use a default body with just the secret.
	RequestBody map[string]string
	Headers     []string
}

// OAuthVerify converts the engine's OAuthVerifyConfig list into the
// shared VerifyEndpoint format and delegates to VerifyCredential.
// The caller is expected to set "oauth2_trace" on the context's logger
// before calling so all log messages carry the correlation ID.
func OAuthVerify(
	ctx context.Context,
	baseClient *http.Client,
	ts detectors.OAuth2TokenSource,
	configs []OAuthVerifyConfig,
	result *detectors.Result,
) (bool, error) {
	logger := logContext.AddLogger(ctx).Logger()
	if len(configs) == 0 {
		logger.Error(nil, "no verification endpoints configured",
			"detector_type", result.DetectorType.String(),
			"detector_name", result.DetectorName,
		)
		return false, fmt.Errorf("no verification endpoints configured")
	}

	if baseClient == nil {
		baseClient = defaultOAuthBaseClient
	}

	// Convert engine configs to the shared VerifyEndpoint format.
	// All endpoints share the same token source in the engine path.
	endpoints := make([]custom_detectors.VerifyEndpoint, len(configs))
	for i, cfg := range configs {
		endpoints[i] = custom_detectors.VerifyEndpoint{
			URL:           cfg.Endpoint,
			Headers:       cfg.Headers,
			SuccessRanges: cfg.SuccessRanges,
			RotatedRanges: cfg.RotatedRanges,
			Body:          cfg.RequestBody,
			TokenSource:   ts,
		}
	}

	vars := map[string]string{
		"$secret":        string(result.Raw),
		"$detector_type": result.DetectorType.String(),
		"$detector_name": result.DetectorName,
	}

	outcome := custom_detectors.VerifyCredential(ctx, baseClient, endpoints, result.Raw, vars)

	if outcome.Attempted && !outcome.Definitive {
		return false, fmt.Errorf("verification attempted but no endpoint gave a definitive answer")
	}
	return outcome.Verified, nil
}
