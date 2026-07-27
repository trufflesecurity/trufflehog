package common

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests made.",
		},
	)

	httpRequestDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
	)

	httpNon200ResponsesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "non_200_responses_total",
			Help:      "Total number of non-200 HTTP responses, labeled by status code.",
		},
		[]string{"status_code"},
	)

	httpResponseBodySizeBytes = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Subsystem: "http_client",
			Name:      "response_body_size_bytes",
			Help:      "Size of HTTP response bodies in bytes.",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 5), // [100B, 1KB, 10KB, 100KB, 1MB]
		},
	)
)

// recordHTTPRequest records metrics for an HTTP request.
func recordHTTPRequest() {
	httpRequestsTotal.Inc()
}

// recordHTTPResponse records metrics for an HTTP response.
func recordHTTPResponse(statusCode int, durationSeconds float64, contentLength int64) {
	// Record latency
	httpRequestDuration.Observe(durationSeconds)

	// Record non-200 responses
	if statusCode != 200 {
		httpNon200ResponsesTotal.WithLabelValues(strconv.Itoa(statusCode)).Inc()
	}

	// Record response body size if known
	if contentLength >= 0 {
		httpResponseBodySizeBytes.Observe(float64(contentLength))
	}
}

// recordNetworkError records metrics for failed HTTP response
func recordNetworkError() {
	httpNon200ResponsesTotal.WithLabelValues("network_error").Inc()
}
