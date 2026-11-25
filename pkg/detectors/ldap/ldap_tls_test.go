package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// selfSignedServer starts a TLS listener whose certificate no client trusts,
// and counts every post-handshake application byte it receives.
func selfSignedServer(t *testing.T) (addr string, gotBytes *atomic.Int64, closeFn func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}

	gotBytes = &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					gotBytes.Add(int64(n))
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), gotBytes, func() { ln.Close() }
}

// A server presenting a certificate the client cannot verify must cause
// verification to fail BEFORE any credential is transmitted, and the failure
// must read as indeterminate rather than as an invalid credential.
func TestVerifyLDAP_UntrustedCertificate(t *testing.T) {
	addr, gotBytes, closeFn := selfSignedServer(t)
	defer closeFn()

	ldapURL, err := url.Parse("ldaps://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	verifyErr := verifyLDAP(ctx, "cn=admin,dc=example,dc=org", "hunter2", ldapURL)
	if verifyErr == nil {
		t.Fatal("expected verification to fail against an untrusted certificate")
	}

	var certErr *tls.CertificateVerificationError
	if !errors.As(verifyErr, &certErr) {
		t.Fatalf("expected a certificate verification error, got: %v", verifyErr)
	}

	if isErrDeterminate(verifyErr) {
		t.Errorf("certificate verification failure must be indeterminate, not an invalid-credential verdict: %v", verifyErr)
	}

	// The handshake was refused client-side, so the credential must never have
	// reached the wire.
	if n := gotBytes.Load(); n != 0 {
		t.Errorf("server received %d application bytes; the bind must not be sent over an unverified channel", n)
	}
}
