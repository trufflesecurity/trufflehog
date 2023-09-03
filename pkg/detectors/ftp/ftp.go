package ftp

import (
	"bytes"
	"context"
	"errors"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc959
	ftpNotLoggedIn = 530

	defaultVerificationTimeout = 5 * time.Second
)

type Scanner struct {
	// Verification timeout. Defaults to 5 seconds if unset.
	verificationTimeout time.Duration
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\bftp://\S{3,50}:(\S{3,50})@[-.%\w/:]+\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("ftp://")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		password := bytes.TrimSpace(match[1])
		trimmedPassword := bytes.Trim(password, "*")
		if bytes.Equal(trimmedPassword, []byte("")) {
			continue
		}

		urlMatch := bytes.TrimSpace(match[0])
		parsedURL, err := url.Parse(string(urlMatch))
		if err != nil {
			continue
		}
		if _, ok := parsedURL.User.Password(); !ok {
			continue
		}
		if parsedURL.User.Username() == "anonymous" {
			continue
		}

		rawURL, _ := url.Parse(string(urlMatch))
		rawURL.Path = ""
		redactStarsBytes := bytes.Repeat([]byte("*"), len(password))
		redact := bytes.Replace([]byte(rawURL.String()), password, redactStarsBytes, -1)

		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_FTP,
			Raw:          []byte(rawURL.String()),
			Redacted:     string(redact),
		}

		if verify {
			timeout := s.verificationTimeout
			if timeout == 0 {
				timeout = defaultVerificationTimeout
			}
			verificationErr := verifyFTP(timeout, parsedURL)
			r.Verified = verificationErr == nil
			if !isErrDeterminate(verificationErr) {
				r.VerificationError = verificationErr
			}
		}

		if !r.Verified {
			// Skip unverified findings where the password starts with a `$` - it's almost certainly a variable.
			if bytes.HasPrefix(password, []byte("$")) {
				continue
			}
		}

		if detectors.IsKnownFalsePositive(r.Raw, []detectors.FalsePositive{[]byte("@ftp.freebsd.org")}, false) {
			continue
		}

		results = append(results, r)
	}

	return results, nil
}

func isErrDeterminate(e error) bool {
	ftpErr := &textproto.Error{}
	return errors.As(e, &ftpErr) && ftpErr.Code == ftpNotLoggedIn
}

func verifyFTP(timeout time.Duration, u *url.URL) error {
	host := u.Host
	if !strings.Contains(host, ":") {
		host = host + ":21"
	}

	c, err := ftp.Dial(host, ftp.DialWithTimeout(timeout))
	if err != nil {
		return err
	}

	password, _ := u.User.Password()
	return c.Login(u.User.Username(), password)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FTP
}
