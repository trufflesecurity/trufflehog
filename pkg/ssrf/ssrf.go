// Package ssrf guards outbound connections whose destinations are taken from
// scanned or otherwise untrusted content (a secret's "domain"/"endpoint",
// a connection string, a URL in a config file). Without a guard, an attacker
// who can plant such content can steer an HTTP client at internal-only
// addresses, and redirects turn an attacker-owned endpoint into a pivot into
// internal space (cluster services, the cloud metadata server, etc.).
//
// The check runs inside the dialer (via ControlContext), after DNS
// resolution and immediately before the socket connects. That placement
// matters for two reasons:
//   - It is DNS-rebinding safe: a hostname that resolves to a public IP on a
//     pre-flight check but to 169.254.169.254 at connect time is still caught,
//     because the check runs on the address actually being dialed.
//   - It covers HTTP redirects: any redirect hop that opens a new connection
//     re-dials through the guarded dialer, and every fresh dial re-checks the
//     resolved IP.
//
// Caveat: the guard inspects the address the transport dials. If an HTTP
// forward proxy is configured (HTTP(S)_PROXY), the transport dials the proxy
// and the proxy makes the final connection, so egress policy must also be
// enforced at the proxy.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrEgressBlocked is wrapped by every error this package returns when it
// refuses a connection. Callers can errors.Is against it to treat a blocked
// egress as an expected, benign outcome rather than a failure.
var ErrEgressBlocked = errors.New("egress blocked: non-public address")

// GuardDialer returns a copy of base (or a zero dialer when base is nil)
// that refuses non-public targets via CheckDialAddress. The check is
// installed as ControlContext because the net package ignores Control
// whenever ControlContext is set: installing the guard as Control would let
// a base dialer carrying a ControlContext bypass it entirely. Any
// ControlContext or Control already set on base runs after the check, for
// allowed targets only.
func GuardDialer(base *net.Dialer) *net.Dialer {
	d := net.Dialer{}
	if base != nil {
		d = *base
	}
	prevCtx, prevCtl := d.ControlContext, d.Control
	d.Control = nil
	d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if err := CheckDialAddress(address); err != nil {
			return err
		}
		if prevCtx != nil {
			return prevCtx(ctx, network, address, c)
		}
		if prevCtl != nil {
			return prevCtl(network, address, c)
		}
		return nil
	}
	return &d
}

// CheckDialAddress rejects a dial target whose IP is not a public address.
// Every rejection wraps ErrEgressBlocked so callers can recognize it. The
// address must be a resolved "ip:port" pair as seen by a dialer Control hook;
// anything else is refused (fail closed).
func CheckDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Fail closed: if we cannot understand the target, do not connect.
		// %v (not %w) on the parse error: a second %w would make this a
		// multi-branch error tree, and whole-tree checks like thog's
		// IsEgressBlockedOnly would classify the rejection as a real failure.
		return fmt.Errorf("ssrf guard: cannot parse dial address %q: %v: %w", address, err, ErrEgressBlocked)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// At dial time the address is already resolved to an IP literal. If it
		// is not, refuse rather than risk connecting to something unvetted.
		return fmt.Errorf("ssrf guard: dial target %q is not an IP literal: %w", host, ErrEgressBlocked)
	}
	if IsNonPublicIP(ip) {
		return fmt.Errorf("ssrf guard: refusing to connect to non-public address %s: %w", ip, ErrEgressBlocked)
	}
	return nil
}

// extraBlockedCIDRs covers ranges not classified by the net.IP helper methods
// but that must never be reachable from guarded egress.
var extraBlockedCIDRs = mustParseCIDRs(
	// IPv4 special-use / non-public ranges.
	"0.0.0.0/8",       // RFC1122 "this network"; parts route to localhost on some stacks
	"100.64.0.0/10",   // RFC6598 CGNAT (incl. Alibaba metadata 100.100.100.200)
	"192.0.0.0/24",    // RFC6890 IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // RFC2544 benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // RFC1112 class E reserved (also covers 255.255.255.255 broadcast)
	// IPv6 embeddings of an IPv4 address that To4() does NOT normalize; without
	// these, an internal v4 target can be smuggled in as an IPv6 literal. The
	// NAT64 well-known prefix is NOT here: DNS64 legitimately synthesizes it for
	// public IPv4-only endpoints, so IsNonPublicIP extracts and classifies the
	// embedded v4 instead (see nat64WellKnownPrefix). The mechanisms below are
	// deprecated or operator-local, so there is no availability reason to allow
	// any of them and they are blocked outright.
	"::/96",           // RFC4291 IPv4-compatible IPv6, deprecated (:: and ::1 are caught earlier)
	"::ffff:0:0:0/96", // RFC2765 SIIT "IPv4-translated"; To4() only normalizes ::ffff:0:0/96
	"64:ff9b:1::/48",  // RFC8215 NAT64 local-use prefix; embedded position varies per operator
	"2002::/16",       // RFC3056 6to4, deprecated
	"2001::/32",       // RFC4380 Teredo; embeds v4 server/client addresses
	// IPv6 ranges with internal or non-routable scope.
	"fec0::/10", // RFC3879 site-local, deprecated but still routed as internal scope by legacy gear
	// IPv6 special-use parity with the v4 test/doc ranges above.
	"2001:db8::/32", // RFC3849 documentation
	"100::/64",      // RFC6666 discard-only
	// Note: IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) is handled by the
	// To4() normalization in IsNonPublicIP, not by a CIDR here, because a
	// ::ffff:0:0/96 entry would match every IPv4 address.
)

// nat64WellKnownPrefix is the RFC6052 NAT64 well-known prefix 64:ff9b::/96.
// Unlike the deprecated embeddings in extraBlockedCIDRs, DNS64 resolvers
// synthesize these addresses for ordinary public IPv4-only endpoints, so
// blanket-blocking the prefix would break every guarded dial to an IPv4-only
// host in an IPv6-only (DNS64/NAT64) network. Instead the embedded IPv4 in
// the low 32 bits is extracted and classified on its own.
var nat64WellKnownPrefix = mustParseCIDRs("64:ff9b::/96")[0]

// IsNonPublicIP reports whether an IP must not be dialed by a guarded client:
// loopback, link-local (incl. cloud metadata), private (RFC1918/RFC4193),
// CGNAT, multicast, unspecified, the special-use ranges above, and IPv6
// embeddings of any of those.
func IsNonPublicIP(ip net.IP) bool {
	if ip == nil {
		return true // fail closed
	}
	// Normalize IPv4-in-IPv6 so the v4 classification methods apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else if ip16 := ip.To16(); ip16 != nil && nat64WellKnownPrefix.Contains(ip16) {
		// NAT64 well-known prefix: classify the embedded IPv4 (low 32 bits) so
		// DNS64-synthesized addresses of public endpoints stay reachable while
		// embeddings of internal targets are still blocked.
		ip = net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15]).To4()
	}

	if ip.IsLoopback() || // 127.0.0.0/8, ::1
		ip.IsUnspecified() || // 0.0.0.0, ::
		ip.IsPrivate() || // RFC1918 (10/8, 172.16/12, 192.168/16) + RFC4193 (fc00::/7)
		ip.IsLinkLocalUnicast() || // 169.254.0.0/16 (metadata 169.254.169.254, ECS creds 169.254.170.2), fe80::/10
		ip.IsMulticast() { // 224.0.0.0/4, ff00::/8 (subsumes link-local and interface-local multicast)
		return true
	}

	for _, n := range extraBlockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("ssrf guard: invalid CIDR %q: %v", c, err))
		}
		nets = append(nets, n)
	}
	return nets
}
