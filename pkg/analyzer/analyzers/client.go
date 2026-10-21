package analyzers

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/ssrf"
	"golang.org/x/time/rate"
)

// restrictEgress gates whether analyzer HTTP clients enforce the SSRF egress
// guard from pkg/ssrf. Analyzers take their endpoints from scanned content (a
// secret's domain, a connection string), so a hosted deployment must refuse
// dials into internal address space. Default false preserves behavior for the
// OSS CLI and self-hosted use, which legitimately analyze credentials for
// internal services.
var restrictEgress atomic.Bool

// SetEgressRestriction enables or disables the analyzer SSRF egress guard.
// When enabled, every client built by this package (NewAnalyzeClient,
// NewAnalyzeClientUnrestricted, HttpStatusTest.RunTest, and the
// RateLimitRoundTripper fallback) refuses to connect to non-public addresses,
// checked after DNS resolution and re-checked on every redirect hop.
func SetEgressRestriction(enabled bool) {
	restrictEgress.Store(enabled)
}

// baseTransport returns the round tripper analyzer clients build on: the
// guarded transport when the egress restriction is enabled, otherwise
// http.DefaultTransport.
func baseTransport() http.RoundTripper {
	if restrictEgress.Load() {
		return safeEgressTransport
	}
	return http.DefaultTransport
}

// safeEgressTransport is http.DefaultTransport with the sole modification of a
// guarded dialer (see ssrf.GuardDialer). Cloning preserves proxy and timeout
// settings; note the pkg/ssrf caveat that a forward proxy moves the final
// connection out of the dialer's sight, so egress policy must then also be
// enforced at the proxy.
var safeEgressTransport = newSafeEgressTransport()

func newSafeEgressTransport() *http.Transport {
	guarded, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		guarded = guarded.Clone()
	} else {
		// http.DefaultTransport is always an *http.Transport; this is a
		// defensive fallback mirroring the standard library's field values.
		guarded = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	// Mirror http.DefaultTransport's dialer (30s timeout and keep-alive).
	guarded.DialContext = ssrf.GuardDialer(&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	return guarded
}

type AnalyzeClient struct {
	http.Client
	LoggingEnabled bool
	LogFile        string
}

func CreateLogFileName(baseName string) string {
	// Get the current time
	currentTime := time.Now()

	// Format the time as "2024_06_30_07_15_30"
	timeString := currentTime.Format("2006_01_02_15_04_05")

	// Create the log file name
	logFileName := fmt.Sprintf("%s_%s.log", timeString, baseName)
	return logFileName
}

type ClientOption func(*http.Client)

// This returns a client that is restricted and filters out unsafe requests returning a success status code.
func NewAnalyzeClient(cfg *config.Config, opts ...func(*http.Client)) *http.Client {
	client := &http.Client{
		Transport: AnalyzerRoundTripper{parent: baseTransport()},
	}
	if cfg != nil && cfg.LoggingEnabled {
		client = &http.Client{
			Transport: LoggingRoundTripper{
				parent:  client.Transport,
				logFile: cfg.LogFile,
			},
		}
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

// This returns a client that is unrestricted and does not filter out unsafe requests returning a success status code.
func NewAnalyzeClientUnrestricted(cfg *config.Config, opts ...ClientOption) *http.Client {
	client := &http.Client{
		Transport: baseTransport(),
	}
	if cfg != nil && cfg.LoggingEnabled {
		client = &http.Client{
			Transport: LoggingRoundTripper{
				parent:  client.Transport,
				logFile: cfg.LogFile,
			},
		}
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

type LoggingRoundTripper struct {
	parent http.RoundTripper
	// TODO: io.Writer
	logFile string
}

func (r LoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	startTime := time.Now()

	resp, parentErr := r.parent.RoundTrip(req)
	if resp == nil {
		return resp, parentErr
	}

	// TODO: JSON
	var logEntry string
	if parentErr != nil {
		logEntry = fmt.Sprintf("Date: %s, Method: %s, Path: %s, Status: %d, Error: %s\n",
			startTime.Format(time.RFC3339),
			req.Method,
			req.URL.Path,
			resp.StatusCode,
			parentErr.Error(),
		)
	} else {
		logEntry = fmt.Sprintf("Date: %s, Method: %s, Path: %s, Status: %d\n",
			startTime.Format(time.RFC3339),
			req.Method,
			req.URL.Path,
			resp.StatusCode,
		)
	}

	// Open log file in append mode.
	file, err := os.OpenFile(r.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return resp, fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Write log entry to file.
	if _, err := file.WriteString(logEntry); err != nil {
		return resp, fmt.Errorf("failed to write log entry to file: %w", err)
	}

	return resp, parentErr
}

type AnalyzerRoundTripper struct {
	parent http.RoundTripper
}

func (r AnalyzerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.parent.RoundTrip(req)
	if err != nil || IsMethodSafe(req.Method) {
		return resp, err
	}
	// Check that unsafe methods did NOT return a valid status code.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, fmt.Errorf("non-safe request returned success")
	}
	return resp, nil
}

// IsMethodSafe is a helper method to check whether the HTTP method is safe according to MDN Web Docs.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods#safe_idempotent_and_cacheable_request_methods
func IsMethodSafe(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

type RateLimitRoundTripper struct {
	parent  http.RoundTripper
	limiter *rate.Limiter
}

func (rt RateLimitRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.parent == nil {
		rt.parent = baseTransport()
	}
	if rt.limiter != nil {
		if err := rt.limiter.Wait(req.Context()); err != nil {
			return nil, err
		}
	}
	return rt.parent.RoundTrip(req)
}

func WithRateLimiter(l *rate.Limiter) ClientOption {
	return func(c *http.Client) {
		c.Transport = RateLimitRoundTripper{
			parent:  c.Transport,
			limiter: l,
		}
	}
}
