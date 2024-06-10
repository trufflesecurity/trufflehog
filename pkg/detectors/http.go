package detectors

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

var DetectorHttpClientWithNoLocalAddresses *http.Client
var DetectorHttpClientWithLocalAddresses *http.Client

const DefaultResponseTimeout = 5 * time.Second
const DefaultUserAgent = "TruffleHog"

func init() {
	DetectorHttpClientWithLocalAddresses = NewDetectorHttpClient(
		WithTransport(NewDetectorTransport(DefaultUserAgent, nil)),
		WithTimeout(DefaultResponseTimeout),
		WithNoFollowRedirects(),
	)
	DetectorHttpClientWithNoLocalAddresses = NewDetectorHttpClient(
		WithTransport(NewDetectorTransport(DefaultUserAgent, nil)),
		WithTimeout(DefaultResponseTimeout),
		WithNoFollowRedirects(),
		WithNoLocalIP(),
	)
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
	T         http.RoundTripper
	userAgent string
}

func (t *detectorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", t.userAgent)
	return t.T.RoundTrip(req)
}

func NewDetectorTransport(userAgent string, T http.RoundTripper) http.RoundTripper {
	if T == nil {
		T = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 5 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   3 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	return &detectorTransport{T: T, userAgent: userAgent}
}

func isLocalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}

	return false
}

func WithNoLocalIP() ClientOption {
	return func(c *http.Client) {
		transport := c.Transport.(*http.Transport)
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
					return nil, errors.New("dialing local IP addresses is not allowed")
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
		Transport: NewDetectorTransport(DefaultUserAgent, nil),
		Timeout:   DefaultResponseTimeout,
	}

	for _, opt := range opts {
		opt(httpClient)
	}
	return httpClient
}
