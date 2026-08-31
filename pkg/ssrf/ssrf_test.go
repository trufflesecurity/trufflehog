package ssrf

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsNonPublicIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		// Public: allowed.
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false}, // example.com
		{"2606:2800:220:1:248:1893:25c8:1946", false},

		// Loopback.
		{"127.0.0.1", true},
		{"127.1.2.3", true},
		{"::1", true},

		// Link-local incl. cloud metadata and ECS credentials endpoint.
		{"169.254.169.254", true}, // GCP/AWS/Azure metadata
		{"169.254.170.2", true},   // AWS ECS task role credentials
		{"fe80::1", true},

		// Private RFC1918 / RFC4193.
		{"10.0.0.5", true},
		{"172.16.31.9", true},
		{"192.168.1.1", true},
		{"fc00::1", true},
		{"fd12:3456::1", true},

		// CGNAT (incl. Alibaba metadata 100.100.100.200).
		{"100.64.0.1", true},
		{"100.100.100.200", true},

		// Unspecified + "this network" 0.0.0.0/8.
		{"0.0.0.0", true},
		{"0.1.2.3", true},
		{"::", true},

		// Class E reserved + broadcast.
		{"240.0.0.1", true},
		{"255.255.255.255", true},

		// Test-net / protocol-assignment ranges.
		{"192.0.2.5", true},
		{"198.18.0.1", true},
		{"203.0.113.9", true},

		// IPv4-mapped IPv6 must not bypass the v4 checks.
		{"::ffff:169.254.169.254", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:8.8.8.8", false},

		// IPv6 embeddings of an internal v4 target (To4() does not normalize these).
		{"64:ff9b::a00:1", true},    // NAT64 of 10.0.0.1
		{"2002:0a00:0001::1", true}, // 6to4 of 10.0.0.1
		{"::0a00:0001", true},       // IPv4-compatible ::10.0.0.1
		{"2001:db8::1", true},       // documentation
	}

	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		require.NotNilf(t, ip, "bad test IP %q", c.ip)
		assert.Equalf(t, c.blocked, IsNonPublicIP(ip), "IsNonPublicIP(%s)", c.ip)
	}

	assert.True(t, IsNonPublicIP(nil), "nil IP must fail closed")
}

func TestCheckDialAddress(t *testing.T) {
	cases := []struct {
		name    string
		address string
		blocked bool
	}{
		{"public IP allowed", "8.8.8.8:443", false},
		{"loopback blocked", "127.0.0.1:8080", true},
		{"metadata blocked", "169.254.169.254:80", true},
		{"IPv6 loopback blocked", "[::1]:443", true},
		{"unparseable address blocked", "no-port-here", true},
		{"unresolved hostname blocked", "example.com:443", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckDialAddress(c.address)
			if !c.blocked {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrEgressBlocked)
			assert.Contains(t, err.Error(), "ssrf guard")
		})
	}
}

// TestGuardDialer_BlocksLoopback drives a real dial through the guarded dialer
// at a loopback httptest server and verifies the refusal carries the sentinel.
func TestGuardDialer_BlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dialer := GuardDialer(nil)
	_, err := dialer.DialContext(context.Background(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEgressBlocked)
}

// TestGuardDialer_ChainsControl verifies an existing Control hook on the base
// dialer still runs (after the guard check) for allowed targets.
func TestGuardDialer_ChainsControl(t *testing.T) {
	var chained bool
	base := &net.Dialer{
		Control: func(_, _ string, _ syscall.RawConn) error {
			chained = true
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Blocked target: the guard refuses before the chained Control runs.
	dialer := GuardDialer(base)
	_, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:1")
	require.ErrorIs(t, err, ErrEgressBlocked)
	assert.False(t, chained, "chained Control must not run for blocked targets")

	// Allowed target: the chained Control runs. The dial itself may fail
	// (network-dependent); only the Control invocation matters here.
	_, _ = dialer.DialContext(ctx, "tcp", "1.1.1.1:53")
	assert.True(t, chained, "chained Control must run for allowed targets")
}

// TestGuardDialer_GuardsBaseWithControlContext locks in the fix for a bypass:
// the net package ignores Control whenever ControlContext is set, so a guard
// installed as Control would never run for a base dialer carrying a
// ControlContext. The guard must win regardless of which hook the base uses.
func TestGuardDialer_GuardsBaseWithControlContext(t *testing.T) {
	var chained bool
	base := &net.Dialer{
		ControlContext: func(_ context.Context, _, _ string, _ syscall.RawConn) error {
			chained = true
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dialer := GuardDialer(base)
	_, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:1")
	require.ErrorIs(t, err, ErrEgressBlocked,
		"a base ControlContext must not bypass the guard")
	assert.False(t, chained, "chained ControlContext must not run for blocked targets")

	// Allowed target: the base's ControlContext still runs after the check.
	_, _ = dialer.DialContext(ctx, "tcp", "1.1.1.1:53")
	assert.True(t, chained, "chained ControlContext must run for allowed targets")
}
