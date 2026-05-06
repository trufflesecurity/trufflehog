package common

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
)

// resetCustomHeaders clears the global CustomHeaders state and registers a
// cleanup that restores it. Tests that mutate feature.CustomHeaders must use
// this helper and must not run in parallel with each other since they share
// global state.
func resetCustomHeaders(t *testing.T) {
	t.Helper()
	feature.CustomHeaders.Store(http.Header{})
	t.Cleanup(func() { feature.CustomHeaders.Store(http.Header{}) })
}

func TestApplyCustomHeaders(t *testing.T) {
	t.Run("no headers configured leaves request untouched", func(t *testing.T) {
		resetCustomHeaders(t)
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("User-Agent", "OriginalUA")

		ApplyCustomHeaders(req)

		assert.Equal(t, "OriginalUA", req.Header.Get("User-Agent"))
		assert.Len(t, req.Header.Values("User-Agent"), 1)
	})

	t.Run("single user value replaces existing default", func(t *testing.T) {
		resetCustomHeaders(t)
		feature.CustomHeaders.Store(http.Header{
			"User-Agent": []string{"MyScanner"},
		})
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("User-Agent", "TruffleHog")

		ApplyCustomHeaders(req)

		assert.Equal(t, []string{"MyScanner"}, req.Header.Values("User-Agent"),
			"first user-supplied value should Set, not Add, so the default is replaced")
	})

	t.Run("multiple values: first sets, rest add", func(t *testing.T) {
		resetCustomHeaders(t)
		feature.CustomHeaders.Store(http.Header{
			"X-Foo": []string{"a", "b", "c"},
		})
		req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("X-Foo", "preexisting")

		ApplyCustomHeaders(req)

		assert.Equal(t, []string{"a", "b", "c"}, req.Header.Values("X-Foo"),
			"preexisting value should be replaced by first user value, then b and c appended")
	})

	t.Run("Load returns a clone: caller mutation does not race", func(t *testing.T) {
		resetCustomHeaders(t)
		feature.CustomHeaders.Store(http.Header{
			"X-Foo": []string{"original"},
		})

		loaded := feature.CustomHeaders.Load()
		loaded.Set("X-Foo", "mutated-by-caller")

		// The next Load must not see the caller's mutation.
		fresh := feature.CustomHeaders.Load()
		assert.Equal(t, "original", fresh.Get("X-Foo"),
			"AtomicHeader.Load must return a defensive copy")
	})
}

// TestCustomTransportSendsCustomHeaders is an end-to-end test that sets
// CustomHeaders, dispatches a request through CustomTransport, and asserts
// the headers arrive at the server. This guards against future changes that
// might bypass ApplyCustomHeaders in the transport chain.
func TestCustomTransportSendsCustomHeaders(t *testing.T) {
	resetCustomHeaders(t)

	feature.CustomHeaders.Store(http.Header{
		"X-Scanner-Id":      []string{"test-scanner"},
		"X-Multi":           []string{"one", "two"},
		"User-Agent":        []string{"OverrideUA"},
		"X-Empty-Value":     []string{""},
	})

	var captured http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{
		Transport: NewCustomTransport(nil),
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "test-scanner", captured.Get("X-Scanner-Id"))
	assert.Equal(t, []string{"one", "two"}, captured.Values("X-Multi"))
	assert.Equal(t, []string{"OverrideUA"}, captured.Values("User-Agent"),
		"user-supplied User-Agent should fully replace the default, not stack")
	require.Contains(t, captured, "X-Empty-Value")
	assert.Equal(t, []string{""}, captured.Values("X-Empty-Value"),
		"empty values are valid per RFC 7230 and must reach the wire")
}

func TestRetryableHTTPClientCheckRetry(t *testing.T) {
	testCases := []struct {
		name            string
		responseStatus  int
		checkRetry      retryablehttp.CheckRetry
		expectedRetries int
	}{
		{
			name:           "Retry on 500 status, give up after 3 retries",
			responseStatus: http.StatusInternalServerError, // Server error status
			checkRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				if err != nil {
					t.Errorf("expected response with 500 status, got error: %v", err)
					return false, err
				}
				// The underlying transport will retry on 500 status.
				if resp.StatusCode == http.StatusInternalServerError {
					return true, nil
				}
				return false, nil
			},
			expectedRetries: 3,
		},
		{
			name:           "No retry on 400 status",
			responseStatus: http.StatusBadRequest, // Client error status
			checkRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				// Do not retry on client errors.
				return false, nil
			},
			expectedRetries: 0,
		},
		{
			name:           "Retry on 429 status, give up after 3 retries",
			responseStatus: http.StatusTooManyRequests,
			checkRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
				if err != nil {
					t.Errorf("expected response with 429 status, got error: %v", err)
					return false, err
				}
				// The underlying transport will retry on 429 status.
				if resp.StatusCode == http.StatusTooManyRequests {
					return true, nil
				}
				return false, nil
			},
			expectedRetries: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var retryCount int

			// Do not count the initial request as a retry.
			i := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i != 0 {
					retryCount++
				}
				i++
				w.WriteHeader(tc.responseStatus)
			}))
			defer server.Close()

			ctx := context.Background()
			client := RetryableHTTPClient(WithCheckRetry(tc.checkRetry), WithTimeout(10*time.Millisecond), WithRetryWaitMin(1*time.Millisecond))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			assert.NoError(t, err)

			// Bad linter, there is no body to close.
			_, err = client.Do(req) //nolint:bodyclose
			if slices.Contains([]int{http.StatusInternalServerError, http.StatusTooManyRequests}, tc.responseStatus) {
				// The underlying transport will retry on 500 and 429 status.
				assert.Error(t, err)
			}

			assert.Equal(t, tc.expectedRetries, retryCount, "Retry count does not match expected")
		})
	}
}

func TestRetryableHTTPClientMaxRetry(t *testing.T) {
	testCases := []struct {
		name            string
		responseStatus  int
		maxRetries      int
		expectedRetries int
	}{
		{
			name:            "Max retries with 500 status",
			responseStatus:  http.StatusInternalServerError,
			maxRetries:      2,
			expectedRetries: 2,
		},
		{
			name:            "Max retries with 429 status",
			responseStatus:  http.StatusTooManyRequests,
			maxRetries:      1,
			expectedRetries: 1,
		},
		{
			name:            "Max retries with 200 status",
			responseStatus:  http.StatusOK,
			maxRetries:      3,
			expectedRetries: 0,
		},
		{
			name:            "Max retries with 400 status",
			responseStatus:  http.StatusBadRequest,
			maxRetries:      3,
			expectedRetries: 0,
		},
		{
			name:            "Max retries with 401 status",
			responseStatus:  http.StatusUnauthorized,
			maxRetries:      3,
			expectedRetries: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var retryCount int

			i := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i != 0 {
					retryCount++
				}
				i++
				w.WriteHeader(tc.responseStatus)
			}))
			defer server.Close()

			client := RetryableHTTPClient(
				WithMaxRetries(tc.maxRetries),
				WithTimeout(10*time.Millisecond),
				WithRetryWaitMin(1*time.Millisecond),
			)

			ctx := context.Background()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			assert.NoError(t, err)

			// Bad linter, there is no body to close.
			_, err = client.Do(req) //nolint:bodyclose
			if err != nil && tc.responseStatus == http.StatusOK {
				assert.Error(t, err)
			}

			assert.Equal(t, tc.expectedRetries, retryCount, "Retry count does not match expected")
		})
	}
}

func TestRetryableHTTPClientBackoff(t *testing.T) {
	testCases := []struct {
		name             string
		responseStatus   int
		expectedRetries  int
		backoffPolicy    retryablehttp.Backoff
		expectedBackoffs []time.Duration
	}{
		{
			name:            "Custom backoff on 500 status",
			responseStatus:  http.StatusInternalServerError,
			expectedRetries: 3,
			backoffPolicy: func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
				switch attemptNum {
				case 1:
					return 1 * time.Millisecond
				case 2:
					return 2 * time.Millisecond
				case 3:
					return 4 * time.Millisecond
				default:
					return max
				}
			},
			expectedBackoffs: []time.Duration{1 * time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var actualBackoffs []time.Duration
			var lastTime time.Time

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				now := time.Now()
				if !lastTime.IsZero() {
					actualBackoffs = append(actualBackoffs, now.Sub(lastTime))
				}
				lastTime = now
				w.WriteHeader(tc.responseStatus)
			}))
			defer server.Close()

			ctx := context.Background()
			client := RetryableHTTPClient(
				WithBackoff(tc.backoffPolicy),
				WithTimeout(10*time.Millisecond),
				WithRetryWaitMin(1*time.Millisecond),
				WithRetryWaitMax(10*time.Millisecond),
			)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			assert.NoError(t, err)

			_, err = client.Do(req) //nolint:bodyclose
			assert.Error(t, err, "Expected error due to 500 status")

			assert.Len(t, actualBackoffs, tc.expectedRetries, "Unexpected number of backoffs")

			for i, expectedBackoff := range tc.expectedBackoffs {
				if i < len(actualBackoffs) {
					// Allow some deviation in timing due to processing delays.
					assert.Less(t, math.Abs(float64(actualBackoffs[i]-expectedBackoff)), float64(15*time.Millisecond), "Unexpected backoff duration")
				}
			}
		})
	}
}

func TestRetryableHTTPClientTimeout(t *testing.T) {
	testCases := []struct {
		name            string
		timeoutSeconds  int64
		expectedTimeout time.Duration
	}{
		{
			name:            "5 second timeout",
			timeoutSeconds:  5,
			expectedTimeout: 5 * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// Call the function with the test timeout value
			client := RetryableHTTPClientTimeout(tc.timeoutSeconds)

			// Verify that the timeout is set correctly
			assert.Equal(t, tc.expectedTimeout, client.Timeout, "HTTP client timeout does not match expected value")

			// Verify that the transport is a custom transport
			_, isRoundTripperTransport := client.Transport.(*retryablehttp.RoundTripper)
			assert.True(t, isRoundTripperTransport, "HTTP client transport is not a retryablehttp.RoundTripper")
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid https URL",
			input:    "https://api.example.com/v1/users",
			expected: "https://api.example.com/v1/users",
		},
		{
			name:     "URL with query parameters",
			input:    "https://api.example.com/search?q=secret&limit=10",
			expected: "https://api.example.com/search",
		},
		{
			name:     "URL with fragment",
			input:    "https://example.com/page#section",
			expected: "https://example.com/page",
		},
		{
			name:     "URL with user info",
			input:    "https://user:pass@api.example.com/path",
			expected: "https://api.example.com/path",
		},
		{
			name:     "empty URL",
			input:    "",
			expected: "unknown",
		},
		{
			name:     "invalid URL",
			input:    "not-a-url",
			expected: "relative_or_invalid",
		},
		{
			name:     "very long path",
			input:    "https://example.com/" + strings.Repeat("a", 150),
			expected: "https://example.com/" + strings.Repeat("a", 99) + "...", // 99 + 1 ("/") = 100 chars
		},
		{
			name:     "root path",
			input:    "https://example.com",
			expected: "https://example.com/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitizeURL(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSaneHttpClientMetrics(t *testing.T) {
	// Create a test server that returns different status codes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/success":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("default"))
		}
	}))
	defer server.Close()

	// Create a SaneHttpClient
	client := SaneHttpClient()

	testCases := []struct {
		name               string
		path               string
		expectedStatusCode int
		expectsNon200      bool
	}{
		{
			name:               "successful request",
			path:               "/success",
			expectedStatusCode: 200,
			expectsNon200:      false,
		},
		{
			name:               "server error request",
			path:               "/error",
			expectedStatusCode: 500,
			expectsNon200:      true,
		},
		{
			name:               "not found request",
			path:               "/notfound",
			expectedStatusCode: 404,
			expectsNon200:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var requestURL string
			if strings.HasPrefix(tc.path, "http") {
				requestURL = tc.path
			} else {
				requestURL = server.URL + tc.path
			}

			// Get initial metric values
			sanitizedURL := sanitizeURL(requestURL)
			initialRequestsTotal := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(sanitizedURL))

			// Make the request
			resp, err := client.Get(requestURL)

			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode)

			// Check that request counter was incremented
			requestsTotal := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(sanitizedURL))
			assert.Equal(t, initialRequestsTotal+1, requestsTotal)
		})
	}
}

func TestRetryableHttpClientMetrics(t *testing.T) {
	// Create a test server that returns different status codes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/success":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("default"))
		}
	}))
	defer server.Close()

	// Create a RetryableHttpClient
	client := RetryableHTTPClient()

	testCases := []struct {
		name               string
		path               string
		expectedStatusCode int
	}{
		{
			name:               "successful request",
			path:               "/success",
			expectedStatusCode: 200,
		},
		{
			name:               "not found request",
			path:               "/notfound",
			expectedStatusCode: 404,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var requestURL string
			if strings.HasPrefix(tc.path, "http") {
				requestURL = tc.path
			} else {
				requestURL = server.URL + tc.path
			}

			// Get initial metric values
			sanitizedURL := sanitizeURL(requestURL)
			initialRequestsTotal := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(sanitizedURL))

			// Make the request
			resp, err := client.Get(requestURL)

			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode)

			// Check that request counter was incremented
			requestsTotal := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(sanitizedURL))
			assert.Equal(t, initialRequestsTotal+1, requestsTotal)
		})
	}
}

func TestInstrumentedTransport(t *testing.T) {
	// Create a mock transport that we can control
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test response"))
	}))
	defer server.Close()

	// Create instrumented transport
	transport := NewInstrumentedTransport(nil)
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	// Get initial metric value
	sanitizedURL := sanitizeURL(server.URL)
	initialCount := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(sanitizedURL))

	// Make a request
	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify the request was successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify metrics were recorded
	finalCount := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(sanitizedURL))
	assert.Equal(t, initialCount+1, finalCount)

	// Note: Testing histogram metrics is complex due to the way Prometheus handles them
	// The main thing is that the request completed successfully and counters were incremented
}
