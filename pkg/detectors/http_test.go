package detectors

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
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
		conn.Close()
	})

	t.Run("Allows dialing non-local IP", func(t *testing.T) {
		client := &http.Client{}
		WithNoLocalIP()(client)

		transport, ok := client.Transport.(*http.Transport)
		assert.True(t, ok, "Expected transport to be *http.Transport")

		conn, err := transport.DialContext(context.Background(), "tcp", "1.1.1.1:80")
		assert.NoError(t, err)
		assert.NotNil(t, conn)
		conn.Close()
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
