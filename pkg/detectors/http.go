package detectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
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

			if slices.ContainsFunc(ips, isLocalIP) {
				return nil, ErrNoLocalIP
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
	client := &http.Client{
		Transport: NewDetectorTransport(nil),
		Timeout:   DefaultResponseTimeout,
	}

	for _, opt := range opts {
		opt(client)
	}

	client.Transport = common.NewInstrumentedTransport(client.Transport)
	return client
}

// bufferedResponse holds a fully-read HTTP response so it can be replayed to
// every goroutine that was coalesced by singleflight.
type bufferedResponse struct {
	statusCode int
	header     http.Header
	body       []byte
}

// singleflightTransport is an http.RoundTripper that coalesces concurrent requests
// sharing the same deduplication key into a single network call. It is a no-op for
// requests whose context does not carry a dedup key.
type singleflightTransport struct {
	base  http.RoundTripper
	group singleflight.Group
}

func (t *singleflightTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key, ok := req.Context().Value(dedupKeyContextKey{}).(string)
	if !ok || key == "" {
		return t.base.RoundTrip(req)
	}

	result, err, _ := t.group.Do(key, func() (any, error) {
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil, err
		}

		return &bufferedResponse{
			statusCode: resp.StatusCode,
			header:     resp.Header.Clone(),
			body:       body,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	br := result.(*bufferedResponse)
	return &http.Response{
		StatusCode: br.statusCode,
		Status:     fmt.Sprintf("%d %s", br.statusCode, http.StatusText(br.statusCode)),
		Header:     br.header.Clone(),
		Body:       io.NopCloser(bytes.NewReader(br.body)),
	}, nil
}

// NewClientWithDedup wraps base with a transport that deduplicates concurrent
// verification requests sharing the same key. Detectors opt in per credential by
// calling WithDedupKey on the request context before client.Do — no other changes
// to request building or response reading are needed.
func NewClientWithDedup(base *http.Client) *http.Client {
	clone := *base
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	clone.Transport = &singleflightTransport{base: transport}
	return &clone
}
