package detectors

import (
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// EndpointSetter implements a sensible default for the SetEndpoints function
// of the EndpointCustomizer interface. A detector can embed this struct to
// gain the functionality.
type EndpointSetter struct {
	endpoints []string
}

func (e *EndpointSetter) SetEndpoints(endpoints ...string) error {
	if len(endpoints) == 0 {
		return fmt.Errorf("at least one endpoint required")
	}
	deduped := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		common.AddStringSliceItem(endpoint, &deduped)
	}
	e.endpoints = deduped
	return nil
}

func (e *EndpointSetter) Endpoints(defaultEndpoint string) []string {
	// The only valid time len(e.endpoints) == 0 is when EndpointSetter is
	// initializetd to its default state. That means SetEndpoints was never
	// called and we should use the default.
	if len(e.endpoints) == 0 {
		return []string{defaultEndpoint}
	}
	return e.endpoints
}
