package detectors

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestWithNoLocalIP(t *testing.T) {
	t.Run("Prevents dialing local IP", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		_, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:8080")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoLocalIP)
	})

	t.Run("Prevents dialing wildcard IP", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		_, err := transport.DialContext(context.Background(), "tcp", "0.0.0.0:8080")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoLocalIP)
	})

	t.Run("Prevents dialing IPv6 wildcard IP", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		_, err := transport.DialContext(context.Background(), "tcp", "[::]:8080")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoLocalIP)
	})

	t.Run("Allows dialing non-local host", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		conn, err := transport.DialContext(context.Background(), "tcp", "google.com:80")
		assert.NoError(t, err)
		assert.NotNil(t, conn)
		_ = conn.Close()
	})

	t.Run("Allows dialing non-local IP", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		conn, err := transport.DialContext(context.Background(), "tcp", "1.1.1.1:80")
		assert.NoError(t, err)
		assert.NotNil(t, conn)
		_ = conn.Close()
	})

	t.Run("Handles invalid address", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		_, err := transport.DialContext(context.Background(), "tcp", "invalid-address")
		assert.Error(t, err)
	})

	t.Run("Handles non-existent hostname", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		_, err := transport.DialContext(context.Background(), "tcp", "non-existent-host.local:80")
		assert.Error(t, err)
	})
}

// TestDoWithDedup_Singleflight verifies that concurrent DoWithDedup calls sharing the
// same detector type and credential are coalesced into one network call. Each request
// the server receives returns a distinct body, so all goroutines should observe the
// body from exactly one actual server-side request.
func TestDoWithDedup_Singleflight(t *testing.T) {
	var requestCount int32

	// The 20 ms sleep keeps the first request in-flight long enough for all
	// goroutines to call DoWithDedup before the result is ready.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		time.Sleep(20 * time.Millisecond)
		_, _ = fmt.Fprintf(w, `{"request":%d}`, n)
	}))
	defer server.Close()

	client := NewClientWithDedup(server.Client())

	const goroutines = 5
	bodies := make([]string, goroutines)
	statuses := make([]int, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
			if err != nil {
				errs[i] = err
				return
			}
			resp, err := DoWithDedup(client, detector_typepb.DetectorType_Meraki, "test-credential", req)
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			var buf [512]byte
			n, _ := resp.Body.Read(buf[:])
			bodies[i] = string(buf[:n])
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		assert.NoError(t, err)
	}
	for _, s := range statuses {
		assert.Equal(t, http.StatusOK, s)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount),
		"singleflight should coalesce all concurrent calls into one HTTP request")
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, bodies[0], bodies[i])
	}
}

// TestDoWithDedup_WaiterContextCancelled verifies that a waiter whose context is
// cancelled bails out with an error while other waiters still receive the response,
// and only one HTTP request is made.
func TestDoWithDedup_WaiterContextCancelled(t *testing.T) {
	var requestCount int32
	// inFlight is closed by the server once it starts handling the request,
	// giving us a reliable signal to cancel one waiter mid-flight.
	inFlight := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		close(inFlight)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithDedup(server.Client())

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	type result struct {
		status int
		err    error
	}
	results := make([]result, 3)
	var wg sync.WaitGroup

	for i, ctx := range []context.Context{ctx1, context.Background(), context.Background()} {
		wg.Add(1)
		go func(i int, ctx context.Context) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
			resp, err := DoWithDedup(client, detector_typepb.DetectorType_Meraki, "cred", req)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			results[i] = result{status: resp.StatusCode}
		}(i, ctx)
	}

	<-inFlight
	cancel1()
	wg.Wait()

	assert.ErrorIs(t, results[0].err, context.Canceled, "cancelled waiter should get context error")
	assert.NoError(t, results[1].err)
	assert.Equal(t, http.StatusOK, results[1].status)
	assert.NoError(t, results[2].err)
	assert.Equal(t, http.StatusOK, results[2].status)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount), "only one HTTP request should be made")
}

// TestDoWithDedup_FirstCallerContextCancelled verifies that cancelling the first
// caller's context does not abort the shared in-flight HTTP call: the second caller
// should still receive a valid response, and only one HTTP request is made.
func TestDoWithDedup_FirstCallerContextCancelled(t *testing.T) {
	var requestCount int32
	inFlight := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		close(inFlight)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithDedup(server.Client())

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	var firstErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := http.NewRequestWithContext(ctx1, http.MethodGet, server.URL, http.NoBody)
		resp, err := DoWithDedup(client, detector_typepb.DetectorType_Meraki, "cred", req)
		if err != nil {
			firstErr = err
			return
		}
		_ = resp.Body.Close()
	}()

	// Cancel the first caller once the server is processing, then immediately
	// start a second caller that should coalesce into the still-running call.
	<-inFlight
	cancel1()

	var secondStatus int
	var secondErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
		resp, err := DoWithDedup(client, detector_typepb.DetectorType_Meraki, "cred", req)
		if err != nil {
			secondErr = err
			return
		}
		defer func() { _ = resp.Body.Close() }()
		secondStatus = resp.StatusCode
	}()

	wg.Wait()

	assert.ErrorIs(t, firstErr, context.Canceled, "first caller should get context error")
	assert.NoError(t, secondErr, "second caller should succeed despite first caller's cancellation")
	assert.Equal(t, http.StatusOK, secondStatus)
	assert.Equal(t, int32(1), atomic.LoadInt32(&requestCount), "only one HTTP request should be made")
}

// TestDoWithDedup_DeadlinePreserved verifies that the client timeout still applies
// to the shared in-flight call after context.WithoutCancel strips cancellation.
// A hanging server must not cause an indefinite leak.
func TestDoWithDedup_DeadlinePreserved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(10 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer server.Close()

	base := server.Client()
	base.Timeout = 75 * time.Millisecond
	client := NewClientWithDedup(base)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, http.NoBody)
	start := time.Now()
	resp, err := DoWithDedup(client, detector_typepb.DetectorType_Meraki, "cred", req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
	}

	elapsed := time.Since(start)

	assert.Error(t, err, "request to hanging server should fail")
	assert.Less(t, elapsed, time.Second, "timeout should be enforced by client deadline, not run indefinitely")
}

func TestIsLocalIP(t *testing.T) {
	testCases := []struct {
		name     string
		ip       net.IP
		expected bool
	}{
		{"Loopback IPv4", net.ParseIP("127.0.0.1"), true},
		{"Loopback IPv6", net.ParseIP("::1"), true},
		{"Private IPv4", net.ParseIP("192.168.1.1"), true},
		{"Private IPv6", net.ParseIP("fd00::1"), true},
		{"Unspecified IPv4", net.ParseIP("0.0.0.0"), true},
		{"Unspecified IPv6", net.ParseIP("::"), true},
		{"Public IPv4", net.ParseIP("8.8.8.8"), false},
		{"Public IPv6", net.ParseIP("2001:4860:4860::8888"), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isLocalIP(tc.ip)
			assert.Equal(t, tc.expected, result)
		})
	}
}
