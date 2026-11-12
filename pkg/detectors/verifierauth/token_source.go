package verifierauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

// defaultTokenLifetime is applied when the identity provider omits
// expires_in from its token response. RFC 6749 makes expires_in optional,
// and oauth2 leaves Expiry zero in that case, which ReuseTokenSource treats
// as "never expires". Without a default, one token would be reused for the
// life of the process and every verification would fail once the IdP
// expired it.
const defaultTokenLifetime = 5 * time.Minute

// ropcTokenSource performs the OAuth2 Resource Owner Password Credentials
// exchange (RFC 6749 section 4.3). It only fetches; caching and refresh are
// layered on top by ReuseTokenSource, and failure backoff by
// tokenErrorCache.
type ropcTokenSource struct {
	conf     *oauth2.Config
	username string
	password string
	// client performs the token request. It is deliberately separate from
	// the detector's client: the token endpoint is the identity provider
	// that issues tokens for the auth proxy, not a verification endpoint, so
	// detector-specific transport rules (such as blocking private IPs) do
	// not apply to it.
	client *http.Client
	now    func() time.Time
	logger func() logr.Logger
}

// newROPCTokenSource builds an unwrapped ROPC token source. Client
// credentials are sent in the request body (AuthStyleInParams) rather than
// as HTTP basic auth, which is what password-grant deployments of the
// identity providers we target expect.
func newROPCTokenSource(
	tokenEndpoint string,
	ropc *custom_detectorspb.ROPCConfig,
	client *http.Client,
	now func() time.Time,
	logger func() logr.Logger,
) *ropcTokenSource {
	return &ropcTokenSource{
		conf: &oauth2.Config{
			ClientID:     ropc.GetClientId(),
			ClientSecret: ropc.GetClientSecret(),
			Endpoint: oauth2.Endpoint{
				TokenURL:  tokenEndpoint,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			Scopes: strings.Fields(ropc.GetScope()),
		},
		username: ropc.GetUsername(),
		password: ropc.GetPassword(),
		client:   client,
		now:      now,
		logger:   logger,
	}
}

// Token fetches a new access token.
//
// oauth2.TokenSource.Token takes no context, so the request context is
// rooted in Background and the HTTP client travels on it under the
// oauth2.HTTPClient key, which is how the oauth2 package selects a client.
// The client's timeout is what bounds a hung identity provider.
func (s *ropcTokenSource) Token() (*oauth2.Token, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.client)

	s.logger().V(2).Info("requesting verifier access token")
	tok, err := s.conf.PasswordCredentialsToken(ctx, s.username, s.password)
	if err != nil {
		return nil, fmt.Errorf("ropc token request failed: %w", err)
	}

	if tok.Expiry.IsZero() {
		tok.Expiry = s.now().Add(defaultTokenLifetime)
		s.logger().V(1).Info("identity provider did not return expires_in; using default token lifetime",
			"default_lifetime", defaultTokenLifetime,
		)
	}
	s.logger().V(1).Info("obtained verifier access token", "expires_at", tok.Expiry)
	return tok, nil
}

// Backoff bounds for tokenErrorCache. The window starts small so a brief
// IdP blip clears quickly, and is capped so that wrong credentials cost at
// most one failed login per maxTokenErrorBackoff, which keeps the scanner
// from tripping the identity provider's account lockout policy.
const (
	minTokenErrorBackoff = 5 * time.Second
	maxTokenErrorBackoff = 5 * time.Minute
)

// tokenErrorCache remembers the most recent token fetch failure and answers
// with it, without contacting the IdP, until a backoff window passes.
// ReuseTokenSource already caches successful tokens; this is the
// counterpart for failures.
//
// It never sleeps. Callers inside a window get the cached error
// immediately, so a failing or hung IdP turns verification for the affected
// auth config into fast "unable to verify" results instead of tying up the
// shared detector worker pool behind token request timeouts. The window
// doubles on each consecutive failure up to maxTokenErrorBackoff and resets
// on the first success.
type tokenErrorCache struct {
	base      oauth2.TokenSource
	now       func() time.Time
	onFailure func(err error, retryIn time.Duration)

	mu      sync.Mutex
	lastErr error
	retryAt time.Time
	window  time.Duration
}

func newTokenErrorCache(base oauth2.TokenSource, now func() time.Time, onFailure func(error, time.Duration)) *tokenErrorCache {
	return &tokenErrorCache{base: base, now: now, onFailure: onFailure}
}

// Token returns a fresh token from the base source, or the cached failure
// while a backoff window is open.
//
// The mutex is held across the base fetch so that, when a window expires,
// exactly one caller makes the next attempt and the rest observe its
// outcome. ReuseTokenSource provides the same serialization in production;
// holding the lock here keeps this type correct on its own.
func (c *tokenErrorCache) Token() (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastErr != nil && c.now().Before(c.retryAt) {
		return nil, fmt.Errorf("token fetch failed recently; next attempt after %s: %w",
			c.retryAt.Format(time.RFC3339), c.lastErr)
	}

	tok, err := c.base.Token()
	if err != nil {
		if c.window == 0 {
			c.window = minTokenErrorBackoff
		} else {
			c.window = min(2*c.window, maxTokenErrorBackoff)
		}
		c.lastErr = err
		c.retryAt = c.now().Add(c.window)
		if c.onFailure != nil {
			c.onFailure(err, c.window)
		}
		return nil, err
	}

	c.lastErr = nil
	c.window = 0
	return tok, nil
}
