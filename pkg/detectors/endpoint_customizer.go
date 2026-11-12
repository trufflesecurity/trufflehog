package detectors

import (
	"fmt"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/verifierauth"
)

// EndpointSetter implements a sensible default for the SetEndpoints function
// of the EndpointCustomizer interface. A detector can embed this struct to
// gain the functionality.
//
// It also implements VerifierAuthCustomizer. Detectors that embed it opt in
// to verifier auth by building their verification client with
// VerificationClient.
type EndpointSetter struct {
	configuredEndpoints []string
	cloudEndpoint       string
	useCloudEndpoint    bool
	useFoundEndpoints   bool
	verifierAuth        *verifierauth.Config
}

func (e *EndpointSetter) SetConfiguredEndpoints(userConfiguredEndpoints ...string) error {
	if len(userConfiguredEndpoints) == 0 {
		return fmt.Errorf("at least one endpoint required")
	}
	deduped := make([]string, 0, len(userConfiguredEndpoints))
	for _, endpoint := range userConfiguredEndpoints {
		common.AddStringSliceItem(endpoint, &deduped)
	}
	e.configuredEndpoints = deduped
	return nil
}

func (e *EndpointSetter) SetCloudEndpoint(url string) {
	e.cloudEndpoint = url
}

func (e *EndpointSetter) UseCloudEndpoint(enabled bool) {
	e.useCloudEndpoint = enabled
}

func (e *EndpointSetter) UseFoundEndpoints(enabled bool) {
	e.useFoundEndpoints = enabled
}

// SetVerifierAuth configures authentication for requests to the configured
// endpoints. A nil config means no auth.
func (e *EndpointSetter) SetVerifierAuth(cfg *verifierauth.Config) {
	e.verifierAuth = cfg
}

// Endpoints returns the endpoints a detector should verify against.
//
// While verifier auth is set, only configured endpoints are returned and the
// cloud and found endpoint flags are ignored. Auth means verification is
// deliberately routed through a private auth proxy, so a secret must never
// be sent to the public API or to an endpoint found in scanned data. The rule is
// applied here, when endpoints are read, rather than by clearing the flags
// in SetVerifierAuth, so a later UseCloudEndpoint(true) from any caller
// cannot re-enable public endpoints.
func (e *EndpointSetter) Endpoints(foundEndpoints ...string) []string {
	endpoints := e.configuredEndpoints
	if e.verifierAuth != nil {
		return endpoints
	}
	if e.useCloudEndpoint && e.cloudEndpoint != "" {
		endpoints = append(endpoints, e.cloudEndpoint)
	}
	if e.useFoundEndpoints {
		endpoints = append(endpoints, foundEndpoints...)
	}
	return endpoints
}

// VerificationClient returns the client a detector should use for
// verification requests: base itself when no verifier auth is configured,
// otherwise a copy of base that attaches the access token to requests for
// the configured endpoints. Detectors call it wherever they would otherwise
// use their verification client directly.
func (e *EndpointSetter) VerificationClient(base *http.Client) *http.Client {
	if e.verifierAuth == nil {
		return base
	}
	return e.verifierAuth.WrapClient(base, e.configuredEndpoints)
}
