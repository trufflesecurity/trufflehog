package detectors

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

var DetectorHttpClientWithNoLocalAddresses *http.Client
var DetectorHttpClientWithLocalAddresses *http.Client

// DefaultResponseTimeout is the default timeout for HTTP requests.
const DefaultResponseTimeout = 10 * time.Second

func userAgent() string {
	if len(feature.UserAgentSuffix.Load()) > 0 {
		return "TruffleHog " + feature.UserAgentSuffix.Load()
	}
	return "TruffleHog"
}

func init() {
	DetectorHttpClientWithLocalAddresses = NewDetectorHttpClient(
		WithTransport(NewDetectorTransport(nil)),
		WithTimeout(DefaultResponseTimeout),
		WithNoFollowRedirects(),
	)
	DetectorHttpClientWithNoLocalAddresses = NewDetectorHttpClient(
		WithTransport(NewDetectorTransport(nil)),
		WithTimeout(DefaultResponseTimeout),
		WithNoFollowRedirects(),
		WithNoLocalIP(),
	)
}

var overrideOnce sync.Once

// OverrideDetectorTimeout overrides the default timeout for the detector HTTP clients.
// It is guaranteed to only run once, subsequent calls will have no effect.
// This should be called before any scans are started.
func OverrideDetectorTimeout(timeout time.Duration) {
    overrideOnce.Do(func() {
        DetectorHttpClientWithLocalAddresses.Timeout = timeout
        DetectorHttpClientWithNoLocalAddresses.Timeout = timeout
    })
}



// ClientOption defines a function type that modifies an http.Client.
type ClientOption func(*http.Client)

// WithNoFollowRedirects allows disabling automatic following of redirects.
func WithNoFollowRedirects() ClientOption {
	return func(c *http.Client) {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
}

type detectorTransport struct {
	T http.RoundTripper
}

func (t *detectorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", userAgent())
	return t.T.RoundTrip(req)
}

var defaultDialer = &net.Dialer{
	Timeout:   2 * time.Second,
	KeepAlive: 5 * time.Second,
}

func NewDetectorTransport(T http.RoundTripper) http.RoundTripper {
	if T == nil {
		T = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           defaultDialer.DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   3 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	return &detectorTransport{T: T}
}

func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}

	return false
}

var ErrNoLocalIP = errors.New("dialing local IP addresses is not allowed")

func WithNoLocalIP() ClientOption {
	return func(c *http.Client) {
		if c.Transport == nil {
			c.Transport = &http.Transport{}
		}

		// Type assertion to get the underlying *http.Transport
		transport, ok := c.Transport.(*http.Transport)
		if !ok {
			// If c.Transport is not *http.Transport, check if it is wrapped in a detectorTransport
			dt, ok := c.Transport.(*detectorTransport)
			if !ok {
				panic("unsupported transport type")
			}
			transport, ok = dt.T.(*http.Transport)
			if !ok {
				panic("underlying transport is not *http.Transport")
			}
		}

		// If the original DialContext is nil, set it to the default dialer
		if transport.DialContext == nil {
			transport.DialContext = defaultDialer.DialContext
		}
		originalDialContext := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, err
			}

			for _, ip := range ips {
				if isLocalIP(ip) {
					return nil, ErrNoLocalIP
				}
			}

			return originalDialContext(ctx, network, net.JoinHostPort(host, port))
		}
	}
}

// WithTransport sets a custom transport for the http.Client.
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(c *http.Client) {
		c.Transport = transport
	}
}

// WithTimeout sets a timeout for the http.Client.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *http.Client) {
		c.Timeout = timeout
	}
}

func NewDetectorHttpClient(opts ...ClientOption) *http.Client {
	httpClient := &http.Client{
		Transport: NewDetectorTransport(nil),
		Timeout:   DefaultResponseTimeout,
	}

	for _, opt := range opts {
		opt(httpClient)
	}
	return httpClient
}
