package engine

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/verifierauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func testVerifierAuth(t *testing.T) *verifierauth.Config {
	t.Helper()
	cfg, err := verifierauth.FromProto(&custom_detectorspb.VerifierAuth{
		AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{Oauth2: &custom_detectorspb.OAuth2Config{
			TokenEndpoint: "https://idp.example.com/token",
			TokenHeader:   "X-Auth-Proxy-Token",
			GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{Ropc: &custom_detectorspb.ROPCConfig{
				Username: "svc", Password: "pw", ClientId: "client",
			}},
		}},
	}, false)
	require.NoError(t, err)
	return cfg
}

func verifierAuthEngineConfig(endpoints map[string]string, auth map[config.DetectorID]*verifierauth.Config) Config {
	return Config{
		Concurrency:       1,
		Detectors:         defaults.DefaultDetectors(),
		Verify:            false,
		SourceManager:     sources.NewManager(),
		Dispatcher:        NewPrinterDispatcher(new(discardPrinter)),
		VerifierEndpoints: endpoints,
		VerifierAuth:      auth,
	}
}

func TestNewEngine_AttachesVerifierAuthToCustomVerifierDetectors(t *testing.T) {
	gitlab := config.DetectorID{ID: detector_typepb.DetectorType_Gitlab}
	conf := verifierAuthEngineConfig(
		map[string]string{"gitlab": "https://authproxy.example.com/gitlab"},
		map[config.DetectorID]*verifierauth.Config{gitlab: testVerifierAuth(t)},
	)

	e, err := NewEngine(context.Background(), &conf)
	require.NoError(t, err)

	type authAware interface {
		Endpoints(...string) []string
		VerificationClient(*http.Client) *http.Client
	}
	var checked int
	base := &http.Client{}
	for _, det := range e.detectors {
		d, ok := det.(authAware)
		if !ok {
			continue
		}
		if det.Type() == detector_typepb.DetectorType_Gitlab {
			// Every GitLab version shares the unversioned auth entry: only the
			// configured endpoint is used, and verification goes through the
			// auth transport.
			assert.Equal(t, []string{"https://authproxy.example.com/gitlab"}, d.Endpoints("https://found.example.com"))
			assert.NotSame(t, base, d.VerificationClient(base))
			checked++
			continue
		}
		assert.Same(t, base, d.VerificationClient(base), "detector %s must not receive auth", det.Type())
	}
	assert.Positive(t, checked, "no GitLab detector found")
}

func TestNewEngine_RejectsVerifierAuthWithoutEndpoints(t *testing.T) {
	gitlab := config.DetectorID{ID: detector_typepb.DetectorType_Gitlab}
	conf := verifierAuthEngineConfig(
		map[string]string{"github": "https://authproxy.example.com/github"},
		map[config.DetectorID]*verifierauth.Config{gitlab: testVerifierAuth(t)},
	)

	_, err := NewEngine(context.Background(), &conf)
	assert.ErrorContains(t, err, "without custom verifier endpoints")
}

func TestValidateVerifierAuth_RejectsDetectorWithoutAuthSupport(t *testing.T) {
	aws := config.DetectorID{ID: detector_typepb.DetectorType_AWS}
	require.NotContains(t, defaults.DefaultDetectorTypesImplementing[detectors.VerifierAuthCustomizer](), aws.ID)

	err := validateVerifierAuth(
		map[config.DetectorID]*verifierauth.Config{aws: testVerifierAuth(t)},
		map[config.DetectorID][]string{aws: {"https://authproxy.example.com"}},
	)
	assert.ErrorContains(t, err, "does not support verifier auth")
}

func TestValidateVerifierAuth_IgnoresNilEntries(t *testing.T) {
	gitlab := config.DetectorID{ID: detector_typepb.DetectorType_Gitlab}
	assert.NoError(t, validateVerifierAuth(map[config.DetectorID]*verifierauth.Config{gitlab: nil}, nil))
}
