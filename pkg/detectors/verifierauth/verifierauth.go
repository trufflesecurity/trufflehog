// Package verifierauth authenticates verification requests to endpoints that
// sit behind an auth proxy: an OAuth-protected component in front of a
// verification service that requires an access token before it forwards a
// request to that service.
//
// Authentication is purely an HTTP-client concern. A Config wraps a
// detector's existing *http.Client so every request to a configured endpoint
// carries an access token, while the detector keeps full ownership of its
// request shape and of how responses map to verdicts. The wrapper never
// decides "verified" or "not verified"; it either attaches a token or fails
// the request, and a failed request surfaces as a verification error
// ("unable to verify").
//
// The package sits below pkg/detectors so that both pkg/detectors
// (EndpointSetter, used by built-in detectors) and pkg/custom_detectors can
// use it. It must never import either of them.
package verifierauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

// DefaultTokenHeader is the header that carries the access token when the
// configuration does not name one.
const DefaultTokenHeader = "Authorization"

// Config is a validated, ready-to-use verifier authentication setup. One
// Config is shared by every request (and every detector worker) that uses
// the same auth block, so its token cache and token error cache are shared
// too. A nil *Config means "no auth configured".
type Config struct {
	tokens        oauth2.TokenSource
	tokenHeader   string
	tokenEndpoint string
	// trace correlates every log line and error produced for this auth
	// config, so an operator can follow one auth block from token fetch
	// through to the verification requests that used it.
	trace string
}

// FromProto validates an auth block and builds a Config from it. It returns
// (nil, nil) when auth is nil, so callers can pass the field through
// unconditionally.
//
// No token is fetched here. Token acquisition is deferred to the first
// verification request that needs one, so an unreachable identity provider
// degrades verification for the affected detector instead of failing
// startup, and the rest of the scan proceeds. Only the structure of the
// config is checked up front.
//
// unsafe has the same meaning as on VerifierConfig: it permits a plain
// http:// token endpoint.
func FromProto(auth *custom_detectorspb.VerifierAuth, unsafe bool) (*Config, error) {
	if auth == nil {
		return nil, nil
	}
	oc := auth.GetOauth2()
	if oc == nil {
		return nil, errors.New("auth is set but names no auth mechanism (expected oauth2)")
	}
	if err := ValidateEndpoint(oc.GetTokenEndpoint(), unsafe); err != nil {
		return nil, fmt.Errorf("oauth2 tokenEndpoint: %w", err)
	}

	tokenHeader := oc.GetTokenHeader()
	if tokenHeader == "" {
		tokenHeader = DefaultTokenHeader
	}
	if !httpguts.ValidHeaderFieldName(tokenHeader) {
		return nil, fmt.Errorf("oauth2 tokenHeader %q is not a valid HTTP header name", tokenHeader)
	}

	ropc := oc.GetRopc()
	if ropc == nil {
		return nil, errors.New("oauth2 auth names no grant (expected ropc)")
	}
	switch {
	case ropc.GetUsername() == "":
		return nil, errors.New("oauth2 ropc username is required")
	case ropc.GetPassword() == "":
		return nil, errors.New("oauth2 ropc password is required")
	case ropc.GetClientId() == "":
		return nil, errors.New("oauth2 ropc clientId is required")
	}

	cfg := &Config{
		tokenHeader:   http.CanonicalHeaderKey(tokenHeader),
		tokenEndpoint: oc.GetTokenEndpoint(),
		trace:         uuid.NewString(),
	}
	base := newROPCTokenSource(oc.GetTokenEndpoint(), ropc, common.SaneHttpClient(), time.Now, cfg.logger)
	errCache := newTokenErrorCache(base, time.Now, func(err error, retryIn time.Duration) {
		cfg.logger().Error(err, "failed to obtain verifier access token; verification for this auth config is unavailable until the retry",
			"retry_in", retryIn,
		)
	})
	// ReuseTokenSource caches the token and refreshes it shortly before it
	// expires. It serializes callers on its own lock while a fetch is in
	// flight, so concurrent detector workers trigger at most one fetch.
	cfg.tokens = oauth2.ReuseTokenSource(nil, errCache)
	return cfg, nil
}

// TokenHeader reports the canonical header name that carries the token.
// Callers that build requests from user-supplied headers use it to reject a
// configuration that would collide with the token at load time.
func (c *Config) TokenHeader() string {
	return c.tokenHeader
}

// logger returns a logger tagged with this config's trace ID. It resolves
// the default logger at call time rather than at construction, so log
// output follows whatever logger the process configured after startup.
func (c *Config) logger() logr.Logger {
	return logContext.Background().Logger().WithValues(
		"oauth2_trace", c.trace,
		"token_endpoint", c.tokenEndpoint,
	)
}

// ValidateEndpoint enforces the transport rule shared by verification
// endpoints and token endpoints: the endpoint must be set, and plain http://
// is only allowed when the verifier is explicitly marked unsafe. It lives
// here, rather than in pkg/custom_detectors, so this package can apply the
// same rule to token endpoints without importing custom_detectors.
func ValidateEndpoint(endpoint string, unsafe bool) error {
	if len(endpoint) == 0 {
		return fmt.Errorf("no endpoint")
	}

	if strings.HasPrefix(endpoint, "http://") && !unsafe {
		return fmt.Errorf("http endpoint must have unsafe=true")
	}
	return nil
}
