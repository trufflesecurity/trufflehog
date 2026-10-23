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

// VerificationClient permits private addresses for initial requests to explicitly
// configured origins (scheme, host, effective port), regardless of URL path or
// endpoint provenance. Unconfigured discovered origins and all redirect hops
// retain the detector's existing network restrictions.
// Verifier authentication, when configured, is applied to configured origins.
// Closing idle connections on the returned client also closes its verification pools.
func (e *EndpointSetter) VerificationClient(base *http.Client) *http.Client {
	client := base
	if len(e.configuredEndpoints) > 0 {
		clone := *base
		transport := base.Transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		origins := make([]verifierOrigin, 0, len(e.configuredEndpoints))
		for _, endpoint := range e.configuredEndpoints {
			u, err := url.Parse(endpoint)
			if err != nil || u.Host == "" {
				continue
			}
			origins = append(origins, verifierOrigin{
				scheme: u.Scheme,
				host:   u.Hostname(),
				port:   verifierPort(u),
			})
		}
		clone.Transport = &configuredVerifierTransport{base: transport, origins: origins}
		client = &clone
	}
	if e.verifierAuth != nil {
		client = e.verifierAuth.WrapClient(client, e.configuredEndpoints)
	}
	return client
}

type verifierOrigin struct {
	scheme string
	host   string
	port   string
}

type configuredVerifierTransport struct {
	base    http.RoundTripper
	origins []verifierOrigin
}

func (t *configuredVerifierTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Response == nil {
		host := req.URL.Hostname()
		port := verifierPort(req.URL)
		for _, origin := range t.origins {
			if !strings.EqualFold(origin.scheme, req.URL.Scheme) ||
				!strings.EqualFold(origin.host, host) || origin.port != port {
				continue
			}
			clone := req.WithContext(context.WithValue(req.Context(), configuredVerifierKey{}, true))
			return t.base.RoundTrip(clone)
		}
	}
	return t.base.RoundTrip(req)
}

func (t *configuredVerifierTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
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
