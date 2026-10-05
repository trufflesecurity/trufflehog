package verifierauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ErrHeaderCollision reports that a request already carries the header the
// access token would be written to. Built-in detectors commonly send the
// secret under test in Authorization; overwriting it would hand the
// verification service the token instead of the secret and produce wrong
// verdicts, so the request is refused instead. The fix is to set tokenHeader
// to a header the auth proxy reads.
var ErrHeaderCollision = errors.New("verifier auth token header is already set by the detector; set oauth2 tokenHeader to a different header")

// WrapClient returns a copy of base whose transport attaches an access token
// to requests bound for allowedEndpoints. Timeout, redirect policy, and
// cookie jar are carried over from base unchanged; base itself is not
// modified.
//
// Only the scheme and host of each allowed endpoint are matched, because
// detectors append their own API paths to the configured endpoint.
// Requests to any other host pass through without a token. The check runs
// on every round trip, so a redirect to another host never carries the
// token either.
func (c *Config) WrapClient(base *http.Client, allowedEndpoints []string) *http.Client {
	clone := *base
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	clone.Transport = &authTransport{
		base:    rt,
		cfg:     c,
		allowed: originsOf(allowedEndpoints),
	}
	return &clone
}

// originsOf reduces endpoints to their lowercase scheme://host form.
// Endpoints that don't parse as absolute URLs contribute nothing, which
// means no token is ever sent on their behalf.
func originsOf(endpoints []string) map[string]struct{} {
	origins := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		origins[origin(u)] = struct{}{}
	}
	return origins
}

// defaultPorts maps each scheme a verifier endpoint may use to the port it
// implies when the URL names none.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// origin reduces u to the lowercase scheme://host[:port] key used for the
// allowlist. url.URL keeps the host exactly as written, so the same server
// can arrive as "https://h" or "https://h:443": the configured endpoint and
// a detector's rebuilt request URL need not agree on spelling. The default
// port for the scheme is dropped so both forms produce one key; dropping it
// (rather than always adding it) matches how endpoints are usually written.
// Non-default ports are kept, so "https://h:8443" stays a different origin.
func origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != defaultPorts[scheme] {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		// Hostname strips the brackets from an IPv6 literal, and
		// JoinHostPort only restores them when there is a port.
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

// authTransport attaches the access token to requests for allowed origins.
type authTransport struct {
	base    http.RoundTripper
	cfg     *Config
	allowed map[string]struct{}
}

// RoundTrip attaches the token and forwards the request, or fails it
// without sending anything. Every failure is returned as a request error,
// which detectors already report as a verification error, never as "not
// verified".
//
// The token is set on a clone because a RoundTripper must not modify the
// caller's request. That also keeps the token off the request http.Client
// reuses to build redirects; each redirect hop comes back through here and
// is checked against the allowlist again.
func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, ok := t.allowed[origin(req.URL)]; !ok {
		return t.base.RoundTrip(req)
	}

	if len(req.Header.Values(t.cfg.tokenHeader)) > 0 {
		closeBody(req)
		return nil, fmt.Errorf("%w (header %q, oauth2_trace=%s)", ErrHeaderCollision, t.cfg.tokenHeader, t.cfg.trace)
	}

	tok, err := t.cfg.tokens.Token()
	if err != nil {
		closeBody(req)
		return nil, fmt.Errorf("verifier auth: obtaining access token (oauth2_trace=%s): %w", t.cfg.trace, err)
	}

	authed := req.Clone(req.Context())
	authed.Header.Set(t.cfg.tokenHeader, "Bearer "+tok.AccessToken)
	return t.base.RoundTrip(authed)
}

// closeBody honors the RoundTripper contract that the request body is
// closed even when RoundTrip returns an error without sending.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
