package detectors

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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

// VerificationClient permits private addresses only for explicitly configured
// endpoints, never for endpoints found in scanned content or redirect hops.
// Verifier authentication, when configured, is applied to the same endpoints.
func (e *EndpointSetter) VerificationClient(base *http.Client) *http.Client {
	client := base
	if len(e.configuredEndpoints) > 0 {
		clone := *base
		transport := base.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		clone.Transport = &configuredVerifierTransport{base: transport, endpoints: e.configuredEndpoints}
		client = &clone
	}
	if e.verifierAuth != nil {
		client = e.verifierAuth.WrapClient(client, e.configuredEndpoints)
	}
	return client
}

type configuredVerifierTransport struct {
	base      http.RoundTripper
	endpoints []string
}

func (t *configuredVerifierTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response == nil {
		for _, endpoint := range t.endpoints {
			u, err := url.Parse(endpoint)
			if err != nil || u.Host == "" || !strings.EqualFold(u.Scheme, req.URL.Scheme) ||
				!strings.EqualFold(u.Hostname(), req.URL.Hostname()) || verifierPort(u) != verifierPort(req.URL) {
				continue
			}
			clone := req.WithContext(context.WithValue(req.Context(), configuredVerifierKey{}, true))
			return t.base.RoundTrip(clone)
		}
	}
	return t.base.RoundTrip(req)
}

func verifierPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}
