package prontunosmtppassword

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"hash/crc32"
	"net"
	"net/smtp"
	"net/textproto"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	// The username can sit well away from the password, so widen the window
	// the engine hands to FromData beyond its single-credential default.
	detectors.DefaultMultiPartCredentialProvider

	// addr and tlsConfig override the production SMTP endpoint in tests.
	addr      string
	tlsConfig *tls.Config
}

// Ensure the Scanner satisfies the interface at compile time.
var (
	_ detectors.Detector                    = (*Scanner)(nil)
	_ detectors.MultiPartCredentialProvider = (*Scanner)(nil)
)

// Prontuno's SMTP submission port. It offers AUTH only after STARTTLS.
const defaultAddr = "smtp.prontuno.net:587"

// verifyTimeout bounds a login attempt when the context has no deadline.
const verifyTimeout = 10 * time.Second

const crockfordAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

var (
	// Prontuno SMTP passwords are pno_sp_<32 random><7 checksum>, all
	// lowercase Crockford base32.
	passwordPat = regexp.MustCompile(`\b(pno_sp_[0-9a-hjkmnp-tv-z]{32})([0-9a-hjkmnp-tv-z]{7})\b`)

	// The SMTP username that pairs with a password is pno_smtp_ followed by
	// a TypeID suffix: 26 Crockford base32 characters, the first one no
	// higher than 7.
	usernamePat = regexp.MustCompile(`\b(pno_smtp_[0-7][0-9a-hjkmnp-tv-z]{25})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pno_sp_"}
}

// FromData will find and optionally verify Prontuno SMTP passwords in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	passwords := make(map[string]struct{})
	for _, match := range passwordPat.FindAllStringSubmatch(dataStr, -1) {
		body, checksum := match[1], match[2]
		// A failed checksum means the match is not a Prontuno-issued password.
		if passwordChecksum(body) != checksum {
			continue
		}
		passwords[body+checksum] = struct{}{}
	}
	if len(passwords) == 0 {
		return nil, nil
	}

	usernames := make(map[string]struct{})
	for _, match := range usernamePat.FindAllStringSubmatch(dataStr, -1) {
		usernames[match[1]] = struct{}{}
	}

	for password := range passwords {
		// Logging in needs the username, so a password found without one is
		// still reported, unverified.
		if len(usernames) == 0 {
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_ProntunoSmtpPassword,
				Raw:          []byte(password),
				SecretParts:  map[string]string{"password": password},
			})
			continue
		}

		for username := range usernames {
			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_ProntunoSmtpPassword,
				Raw:          []byte(password),
				RawV2:        []byte(username + ":" + password),
				SecretParts:  map[string]string{"username": username, "password": password},
			}

			if verify {
				isVerified, vErr := verifyLogin(ctx, cmp.Or(s.addr, defaultAddr), s.tlsConfig, username, password)
				r.Verified = isVerified
				r.SetVerificationError(vErr, password)
			}

			results = append(results, r)

			// A password belongs to exactly one username, so once a pair
			// verifies, the remaining usernames can only fail.
			if r.Verified {
				break
			}
		}
	}

	return results, nil
}

// passwordChecksum mirrors Prontuno's issuer: CRC32 (IEEE) of everything
// before the checksum, written big-endian as seven Crockford base32 digits.
func passwordChecksum(body string) string {
	sum := crc32.ChecksumIEEE([]byte(body))
	out := make([]byte, 7)
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = crockfordAlphabet[sum%32]
		sum /= 32
	}
	return string(out)
}

// verifyLogin upgrades the connection with STARTTLS, authenticates against
// Prontuno's SMTP service and disconnects without sending mail.
//
// The error is non-nil only when verification is indeterminate. The server
// answers 535 to an unknown, revoked, disabled or mismatched credential;
// any other failure says nothing about the credential.
func verifyLogin(ctx context.Context, addr string, tlsConfig *tls.Config, username, password string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, verifyTimeout)
		defer cancel()
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	// net/smtp does not take a context, so closing the connection is what
	// stops a login attempt when the context ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return false, err
	}
	defer func() { _ = client.Close() }()

	tlsConfig = tlsConfig.Clone()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = host
	}
	if err := client.StartTLS(tlsConfig); err != nil {
		return false, err
	}

	if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
		var smtpErr *textproto.Error
		if errors.As(err, &smtpErr) && smtpErr.Code == 535 {
			return false, nil
		}
		return false, err
	}

	_ = client.Quit()
	return true, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ProntunoSmtpPassword
}

func (s Scanner) Description() string {
	return "Prontuno is a transactional email service. A Prontuno SMTP password, together with its SMTP username, can send email from the domain the credential belongs to."
}
