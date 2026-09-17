package detectors

import (
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// EndpointSetter implements a sensible default for the SetEndpoints function
// of the EndpointCustomizer interface. A detector can embed this struct to
// gain the functionality. When a custom verifier has OAuth2 auth configured,
// the engine sets a token source here so the scan loop can route verification
// through the OAuthVerifier interface instead of the detector's built-in path.
type EndpointSetter struct {
	configuredEndpoints []string
	cloudEndpoint       string
	useCloudEndpoint    bool
	useFoundEndpoints   bool
	oauth2Source        OAuth2TokenSource
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

func (e *EndpointSetter) Endpoints(foundEndpoints ...string) []string {
	endpoints := e.configuredEndpoints
	if e.useCloudEndpoint && e.cloudEndpoint != "" {
		endpoints = append(endpoints, e.cloudEndpoint)
	}
	if e.useFoundEndpoints {
		endpoints = append(endpoints, foundEndpoints...)
	}
	return endpoints
}

// SetOAuth2TokenSource configures an OAuth2 token source for this
// detector's custom verifier. When set, the engine uses OAuthVerifier-based
// verification instead of the detector's built-in verification logic.
func (e *EndpointSetter) SetOAuth2TokenSource(ts OAuth2TokenSource) { e.oauth2Source = ts }

// HasOAuth2 reports whether OAuth2 auth is configured for this
// detector's custom verifier endpoint.
func (e *EndpointSetter) HasOAuth2() bool { return e.oauth2Source != nil }

// OAuth2TokenSource returns the configured OAuth2 token source, or nil
// if no auth is configured.
func (e *EndpointSetter) OAuth2TokenSource() OAuth2TokenSource { return e.oauth2Source }
