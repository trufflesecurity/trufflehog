package prontunosmtppassword

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Synthetic credentials in the exact shape Prontuno issues, with valid
// checksums. Not real credentials.
const (
	validPassword = "pno_sp_0123456789abcdefghjkmnpqrstvwxyz2cp0asg"
	otherPassword = "pno_sp_zyxwvtsrqpnmkjhgfedcba98765432100d5x1sw"
	validUsername = "pno_smtp_01kxh2fjk3e00b2n8r6ysx4d7k"
)

func TestProntunoSmtpPassword_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - password with username",
			input: `
				MAIL_HOST=smtp.prontuno.net
				MAIL_USERNAME=` + validUsername + `
				MAIL_PASSWORD=` + validPassword,
			want: []string{validUsername + ":" + validPassword},
		},
		{
			name:  "valid pattern - smtp url",
			input: `smtp://` + validUsername + `:` + validPassword + `@smtp.prontuno.net:587`,
			want:  []string{validUsername + ":" + validPassword},
		},
		{
			name:  "valid pattern - password without username",
			input: `MAIL_PASSWORD="` + validPassword + `"`,
			want:  []string{validPassword},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: validPassword + " " + validPassword,
			want:  []string{validPassword},
		},
		{
			name:  "valid pattern - two passwords",
			input: validPassword + " " + otherPassword,
			want:  []string{validPassword, otherPassword},
		},
		{
			name:  "invalid pattern - checksum mismatch",
			input: `MAIL_PASSWORD=pno_sp_0123456789abcdefghjkmnpqrstvwxyz2cp0ash`,
			want:  nil,
		},
		{
			name:  "invalid pattern - letter outside the alphabet",
			input: `MAIL_PASSWORD=pno_sp_0123456789abcdefghijkmnpqrstvwxyz2cp0as`,
			want:  nil,
		},
		{
			name:  "invalid pattern - too short",
			input: `MAIL_PASSWORD=` + validPassword[:len(validPassword)-1],
			want:  nil,
		},
		{
			name:  "invalid pattern - too long",
			input: `MAIL_PASSWORD=` + validPassword + `0`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, received %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
				if r.SecretParts["password"] != string(r.Raw) {
					t.Errorf("SecretParts[password] = %q, want %q", r.SecretParts["password"], r.Raw)
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

// smtpServer is a minimal SMTP server that offers AUTH only after STARTTLS,
// like Prontuno's submission port. It answers every
// AUTH PLAIN with authReply, except that the validUsername/validPassword
// pair gets 235 when acceptValid is set. A reply of "" makes the server
// hang up instead of answering.
type smtpServer struct {
	addr        string
	tlsConfig   *tls.Config
	serverTLS   *tls.Config
	logins      atomic.Int32
	authReply   string
	acceptValid bool
}

func newSMTPServer(t *testing.T, authReply string, acceptValid bool) *smtpServer {
	t.Helper()

	// Borrow httptest's certificate, which is valid for 127.0.0.1.
	hs := httptest.NewUnstartedServer(nil)
	hs.StartTLS()
	cert := hs.TLS.Certificates[0]
	hs.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	s := &smtpServer{
		addr:        ln.Addr().String(),
		tlsConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server with a self-signed certificate
		serverTLS:   &tls.Config{Certificates: []tls.Certificate{cert}},
		authReply:   authReply,
		acceptValid: acceptValid,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()

	return s
}

func (s *smtpServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	reply := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	reply("220 test ESMTP")

	secure := false
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "EHLO"):
			reply("250-test")
			if secure {
				reply("250 AUTH PLAIN LOGIN")
			} else {
				reply("250 STARTTLS")
			}
		case line == "STARTTLS" && !secure:
			reply("220 Go ahead")
			conn = tls.Server(conn, s.serverTLS)
			scanner = bufio.NewScanner(conn)
			secure = true
		case strings.HasPrefix(line, "AUTH PLAIN ") && secure:
			s.logins.Add(1)
			decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
			if s.acceptValid && string(decoded) == "\x00"+validUsername+"\x00"+validPassword {
				reply("235 2.7.0 Authentication successful")
				continue
			}
			if s.authReply == "" {
				return
			}
			reply(s.authReply)
		case strings.HasPrefix(line, "QUIT"):
			reply("221 bye")
			return
		default:
			reply("502 command not implemented")
		}
	}
}

func TestProntunoSmtpPassword_Verification(t *testing.T) {
	pair := "MAIL_USERNAME=" + validUsername + "\nMAIL_PASSWORD=" + validPassword

	tests := []struct {
		name         string
		input        string
		authReply    string
		acceptValid  bool
		wantVerified bool
		wantErr      bool
		wantLogins   int32
	}{
		{
			name:         "235 verifies",
			input:        pair,
			authReply:    "535 5.7.8 Authentication failed",
			acceptValid:  true,
			wantVerified: true,
			wantLogins:   1,
		},
		{
			name:       "535 determinately invalid",
			input:      pair,
			authReply:  "535 5.7.8 Authentication failed",
			wantLogins: 1,
		},
		{
			name:       "454 temporary failure is indeterminate",
			input:      pair,
			authReply:  "454 4.7.0 Temporary authentication failure",
			wantErr:    true,
			wantLogins: 1,
		},
		{
			name:       "421 service unavailable is indeterminate",
			input:      pair,
			authReply:  "421 4.3.0 Service not available",
			wantErr:    true,
			wantLogins: 1,
		},
		{
			name:       "dropped connection is indeterminate",
			input:      pair,
			authReply:  "",
			wantErr:    true,
			wantLogins: 1,
		},
		{
			name:        "password without username is not sent for verification",
			input:       "MAIL_PASSWORD=" + validPassword,
			acceptValid: true,
			wantLogins:  0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := newSMTPServer(t, test.authReply, test.acceptValid)

			d := Scanner{addr: srv.addr, tlsConfig: srv.tlsConfig}
			results, err := d.FromData(context.Background(), true, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			r := results[0]
			if r.Verified != test.wantVerified {
				t.Errorf("Verified = %v, want %v", r.Verified, test.wantVerified)
			}
			if (r.VerificationError() != nil) != test.wantErr {
				t.Errorf("VerificationError = %v, wantErr = %v", r.VerificationError(), test.wantErr)
			}
			if got := srv.logins.Load(); got != test.wantLogins {
				t.Errorf("logins = %d, want %d", got, test.wantLogins)
			}
		})
	}
}

func TestProntunoSmtpPassword_StopsAfterVerifiedPair(t *testing.T) {
	srv := newSMTPServer(t, "535 5.7.8 Authentication failed", true)

	input := "MAIL_PASSWORD=" + validPassword + "\n" +
		"pno_smtp_01aaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"pno_smtp_01bbbbbbbbbbbbbbbbbbbbbbbb\n" +
		"pno_smtp_01cccccccccccccccccccccccc\n" +
		"pno_smtp_01dddddddddddddddddddddddd\n" +
		validUsername + "\n"

	// Usernames come out of a map in random order, so repeat to make a
	// missing early exit show up as a verified result that is not last.
	d := Scanner{addr: srv.addr, tlsConfig: srv.tlsConfig}
	for i := 0; i < 10; i++ {
		srv.logins.Store(0)
		results, err := d.FromData(context.Background(), true, []byte(input))
		if err != nil {
			t.Fatalf("FromData: %v", err)
		}
		if got := srv.logins.Load(); got != int32(len(results)) {
			t.Fatalf("logins = %d, want one per result (%d)", got, len(results))
		}
		last := results[len(results)-1]
		if !last.Verified || last.SecretParts["username"] != validUsername {
			t.Fatalf("last result = verified %v for %q, want the verified pair for %q",
				last.Verified, last.SecretParts["username"], validUsername)
		}
		for _, r := range results[:len(results)-1] {
			if r.Verified || r.VerificationError() != nil {
				t.Fatalf("pair for %q: verified %v, error %v; want determinately invalid",
					r.SecretParts["username"], r.Verified, r.VerificationError())
			}
		}
	}
}

func TestProntunoSmtpPassword_UnreachableServerIsIndeterminate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	d := Scanner{addr: addr}
	results, err := d.FromData(context.Background(), true,
		[]byte("MAIL_USERNAME="+validUsername+"\nMAIL_PASSWORD="+validPassword))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 || results[0].Verified || results[0].VerificationError() == nil {
		t.Fatalf("want one unverified result with a verification error, got %+v", results)
	}
}

func TestProntunoSmtpPassword_CancelledContextIsIndeterminate(t *testing.T) {
	srv := newSMTPServer(t, "535 5.7.8 Authentication failed", true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verified, err := verifyLogin(ctx, srv.addr, srv.tlsConfig, validUsername, validPassword)
	if verified || err == nil {
		t.Errorf("verifyLogin = (%v, %v), want (false, non-nil error)", verified, err)
	}
}
