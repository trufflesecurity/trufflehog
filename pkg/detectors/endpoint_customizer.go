package detectors

import (
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// EndpointSetter implements a sensible default for the SetEndpoints function
// of the EndpointCustomizer interface. A detector can embed this struct to
// gain the functionality.
type EndpointSetter struct {
	configuredEndpoints []string
	cloudEndpoint       string
	useCloudEndpoint    bool
	useFoundEndpoints   bool
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
