package detectors

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// EndpointSetter implements a sensible default for the SetEndpoints function
// of the EndpointCustomizer interface. A detector can embed this struct to
// gain the functionality. See Endpoints for the order sources are tried in.
type EndpointSetter struct {
	configuredEndpoints []string

	cloudEndpoints   []string
	useCloudEndpoints bool

	useFoundEndpoints bool
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

// SetCloudEndpoints sets the provider's default (non-user-configured)
// endpoints. Most providers have one; some (gov-cloud, regional deployments)
// have several, all tried in the given order.
func (e *EndpointSetter) SetCloudEndpoints(cloudEndpoints ...string) {
	deduped := make([]string, 0, len(cloudEndpoints))
	for _, endpoint := range cloudEndpoints {
		if endpoint == "" {
			continue
		}
		common.AddStringSliceItem(endpoint, &deduped)
	}
	e.cloudEndpoints = deduped
}

func (e *EndpointSetter) UseCloudEndpoints(enabled bool) {
	e.useCloudEndpoints = enabled
}

func (e *EndpointSetter) UseFoundEndpoints(enabled bool) {
	e.useFoundEndpoints = enabled
}

// Endpoints returns the endpoints to try, in order: configured, then cloud,
// then found. Found endpoints are last and never precede the others, because
// they come from attacker-controlled scanned content, not operator intent.
//
// allowedFoundSuffixes is optional and applies only to foundEndpoints: when
// given, a found endpoint is only included if its host ends in one of these
// suffixes (e.g. ".jira.com"), guarding against a scanned chunk steering
// verification at an arbitrary host (SSRF). Configured and cloud endpoints
// are never filtered - they're operator/developer trusted, not scanned text.
func (e *EndpointSetter) Endpoints(foundEndpoints []string, allowedFoundSuffixes ...string) []string {
	endpoints := make([]string, 0, len(e.configuredEndpoints)+len(e.cloudEndpoints)+len(foundEndpoints))
	seen := make(map[string]struct{}, cap(endpoints))
	add := func(endpoint string) {
		if _, ok := seen[endpoint]; ok {
			return
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}

	// Deduped across all three sources, not just within each: the same host
	// can legitimately show up as both configured and found (or cloud and
	// found), and callers counting distinct endpoints (e.g. to decide whether
	// a match is confident) need one entry per host, not one per source.
	for _, endpoint := range e.configuredEndpoints {
		add(endpoint)
	}

	if e.useCloudEndpoints {
		for _, endpoint := range e.cloudEndpoints {
			add(endpoint)
		}
	}

	if e.useFoundEndpoints {
		for _, found := range foundEndpoints {
			if foundEndpointAllowed(found, allowedFoundSuffixes) {
				add(found)
			}
		}
	}

	return endpoints
}

func foundEndpointAllowed(rawURL string, allowedSuffixes []string) bool {
	if len(allowedSuffixes) == 0 {
		return true
	}
	host := hostOf(rawURL)
	if host == "" {
		return false
	}
	for _, suffix := range allowedSuffixes {
		if strings.HasSuffix(host, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

// hostOf extracts the lowercased hostname (no port) from rawURL. rawURL may
// or may not include a scheme - detectors' found-endpoint regexes vary
// (some match full URLs, some match bare hostnames) - so a bare hostname is
// reparsed with a scheme to get url.Parse to populate Host at all. Never
// falls back to matching against the raw string: an unparseable or
// ambiguous value must not slip past the suffix check.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if u.Host == "" {
		u, err = url.Parse("https://" + rawURL)
		if err != nil {
			return ""
		}
	}
	return strings.ToLower(u.Hostname())
}
