package common

import (
	"net/url"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests made, labeled by URL.",
		},
		[]string{"url"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency in seconds, labeled by URL.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"url"},
	)

	httpNon200ResponsesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "non_200_responses_total",
			Help:      "Total number of non-200 HTTP responses, labeled by URL and status code.",
		},
		[]string{"url", "status_code"},
	)

	httpResponseBodySizeBytes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "response_body_size_bytes",
			Help:      "Size of HTTP response bodies in bytes, labeled by URL.",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 5), // [100B, 1KB, 10KB, 100KB, 1MB]
		},
		[]string{"url"},
	)
)

// sanitizeURL sanitizes a URL to avoid high cardinality metrics.
// It keeps only the host and path, removing query parameters, fragments, and user info.
func sanitizeURL(rawURL string) string {
	if rawURL == "" {
		return "unknown"
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "invalid_url"
	}

	// Build sanitized URL with just scheme, host, and path
	sanitized := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   parsedURL.Path,
	}

	// If host is empty, try to extract from the raw URL
	if sanitized.Host == "" {
		// For relative URLs or malformed URLs, just use a placeholder
		return "relative_or_invalid"
	}

	// Normalize path
	if sanitized.Path == "" {
		sanitized.Path = "/"
	}

	// Limit path length to avoid extremely long paths creating high cardinality
	if len(sanitized.Path) > 100 {
		sanitized.Path = sanitized.Path[:100] + "..."
	}

	result := sanitized.String()

	// Final fallback to avoid empty strings
	if result == "" {
		return "unknown"
	}

	return result
}

// recordHTTPRequest records metrics for an HTTP request.
func recordHTTPRequest(sanitizedURL string) {
	httpRequestsTotal.WithLabelValues(sanitizedURL).Inc()
}

// recordHTTPResponse records metrics for an HTTP response.
func recordHTTPResponse(sanitizedURL string, statusCode int, durationSeconds float64) {
	// Record latency
	httpRequestDuration.WithLabelValues(sanitizedURL).Observe(durationSeconds)

	// Record non-200 responses
	if statusCode != 200 {
		httpNon200ResponsesTotal.WithLabelValues(sanitizedURL, strconv.Itoa(statusCode)).Inc()
	}
}

// recordNetworkError records metrics for failed HTTP response
func recordNetworkError(sanitizedURL string) {
	httpNon200ResponsesTotal.WithLabelValues(sanitizedURL, "network_error").Inc()
}

// recordResponseBodySize records metrics for the size of an HTTP response body.
func recordResponseBodySize(sanitizedURL string, sizeBytes int) {
	httpResponseBodySizeBytes.WithLabelValues(sanitizedURL).Observe(float64(sizeBytes))
}
