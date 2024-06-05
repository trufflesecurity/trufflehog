package roundtripper

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type RoundTripper struct {
	logger   logr.Logger
	original http.RoundTripper
	*BasicAuthRoundTripper
	*RetryableRoundtripper
	*LoggingRoundtripper
}

type BasicAuthRoundTripper struct {
	username, password string
}

type RetryableRoundtripper struct {
	enabled                  bool
	maxRetries               uint
	shouldRetryError         bool
	shouldRetryErrorDuration time.Duration
	shouldRetry5XX           bool
	shouldRetry5XXDuration   time.Duration
	shouldRetry401           bool
	shouldRetry401Duration   time.Duration
	default429RetryDuration  time.Duration
}

type LoggingRoundtripper struct{}

// NewRoundTripper creates a new RoundTripper instance tailored for the application's specific needs.
// This custom RoundTripper provides a centralized place to manage outbound HTTP requests.
// By allowing configuration through functional options, it provides a clear, extensible, and maintainable
// way to adjust the behavior of HTTP calls. This ensures consistent logging, error handling,
// and other behaviors across all HTTP requests made in the application, reducing potential points of
// failure and simplifying debugging.
func NewRoundTripper(original http.RoundTripper, opts ...func(*RoundTripper)) *RoundTripper {
	r := &RoundTripper{
		logger:                context.Background().Logger().WithValues("component", "basic_auth_roundtripper"),
		original:              original,
		RetryableRoundtripper: &RetryableRoundtripper{enabled: false},
	}

	if original == nil {
		r.original = common.NewCustomTransport(nil)
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

func (r *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	retries := 0
	for {
		logger := r.logger.WithValues(
			"method", req.Method,
			"url", req.URL,
		)

		if r.BasicAuthRoundTripper != nil {
			req.SetBasicAuth(r.BasicAuthRoundTripper.username, r.BasicAuthRoundTripper.password)
		}

		authMethod := determineAuth(req)
		if r.LoggingRoundtripper != nil {
			logger.V(5).Info(fmt.Sprintf("sending request with %s", authMethod))
		}

		response, err := r.original.RoundTrip(req)
		if err != nil {
			logger.V(5).Info("got error while sending request",
				"error", err,
			)
		}

		if r.LoggingRoundtripper != nil && response != nil {
			logger.V(5).Info("got response",
				"status_code", response.StatusCode,
			)
		}

		reason, shouldRetry, duration := r.RetryableRoundtripper.shouldRetryRequest(response, err)
		if shouldRetry {
			if retries >= int(r.RetryableRoundtripper.maxRetries) {
				r.logger.V(2).Info("max retries reached",
					"host", req.Host,
					"reason", reason,
					"retries", retries,
				)
				return response, err
			}
			r.logger.V(2).Info("retrying request",
				"host", req.Host,
				"reason", reason,
				"retries", retries,
			)

			retries++
			time.Sleep(duration)
			continue
		}

		return response, err
	}
}

// WithInsecureTLS will disable TLS verification.
func WithInsecureTLS() func(*RoundTripper) {
	return func(r *RoundTripper) {
		r.original = common.NewCustomTransport(&http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		})
	}
}

func WithLogger(log logr.Logger) func(*RoundTripper) {
	return func(r *RoundTripper) {
		r.logger = log
	}
}

// Logging

func WithLogging() func(*RoundTripper) {
	return func(r *RoundTripper) {
		r.LoggingRoundtripper = &LoggingRoundtripper{}
	}
}

// Basic Auth

func WithBasicAuth(username, password string) func(*RoundTripper) {
	return func(r *RoundTripper) {
		r.BasicAuthRoundTripper = &BasicAuthRoundTripper{
			username: username,
			password: password,
		}
	}
}

// Retryable

func (r *RetryableRoundtripper) shouldRetryRequest(response *http.Response, err error) (reason string, shouldRetry bool, after time.Duration) {
	if !r.enabled {
		return "", false, 0
	}

	if err != nil {
		return err.Error(), r.shouldRetryError, r.shouldRetryErrorDuration
	}

	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		retryAfter := getRetryAfter(response)
		if retryAfter == 0 {
			retryAfter = r.default429RetryDuration
		}
		return strconv.Itoa(response.StatusCode), true, retryAfter
	}

	code := response.StatusCode
	switch {
	case code == 401:
		return strconv.Itoa(response.StatusCode), r.shouldRetry401, r.shouldRetry401Duration
	case code >= 500:
		return strconv.Itoa(response.StatusCode), r.shouldRetry5XX, r.shouldRetry5XXDuration
	default:
		return "", false, 0
	}
}

func getRetryAfter(response *http.Response) time.Duration {
	if s, ok := response.Header["Retry-After"]; ok {
		if sleep, err := strconv.ParseInt(s[0], 10, 64); err == nil {
			return time.Second * time.Duration(sleep)
		}
	}
	return 0
}

func WithRetryable(opts ...func(*RetryableRoundtripper)) func(*RoundTripper) {
	return func(r *RoundTripper) {
		rt := &RetryableRoundtripper{
			enabled:                  true,
			maxRetries:               3,
			shouldRetryError:         true,
			shouldRetryErrorDuration: time.Second * 5,
			shouldRetry5XX:           true,
			shouldRetry5XXDuration:   time.Second * 5,
			shouldRetry401:           false,
			shouldRetry401Duration:   time.Second * 5,
			default429RetryDuration:  time.Second * 30,
		}

		for _, opt := range opts {
			opt(rt)
		}

		r.RetryableRoundtripper = rt
	}
}

func WithShouldRetryError(should bool) func(*RetryableRoundtripper) {
	return func(r *RetryableRoundtripper) {
		r.shouldRetryError = should
	}
}

func WithShouldRetryErrorDuration(duration time.Duration) func(*RetryableRoundtripper) {
	return func(r *RetryableRoundtripper) {
		r.shouldRetryErrorDuration = duration
	}
}

func WithShouldRetry5XX(should bool) func(*RetryableRoundtripper) {
	return func(r *RetryableRoundtripper) {
		r.shouldRetry5XX = should
	}
}

func WithShouldRetry5XXDuration(duration time.Duration) func(*RetryableRoundtripper) {
	return func(r *RetryableRoundtripper) {
		r.shouldRetry5XXDuration = duration
	}
}

func WithShouldRetry401Duration(duration time.Duration) func(*RetryableRoundtripper) {
	return func(r *RetryableRoundtripper) {
		r.shouldRetry401 = true
		r.shouldRetry401Duration = duration
	}
}

func WithDefault429RetryDuration(duration time.Duration) func(*RetryableRoundtripper) {
	return func(r *RetryableRoundtripper) {
		r.default429RetryDuration = duration
	}
}

func WithMaxRetries(max uint) func(*RetryableRoundtripper) {
	return func(r *RetryableRoundtripper) {
		r.maxRetries = max
	}
}

// determineAuth will let us know if the Authorization header is set,
// and if it is, if it contains the prefix "Basic" or "Bearer"
func determineAuth(req *http.Request) string {
	switch authHeader := req.Header.Get("Authorization"); true {
	case authHeader == "":
		return "no auth"
	case strings.HasPrefix(authHeader, "Basic"):
		return "basic auth"
	case strings.HasPrefix(authHeader, "Bearer"):
		return "bearer token"
	default:
		return "unknown auth"
	}
}
