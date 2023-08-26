package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	uriPat      = regexp.MustCompile(`\b(?i)ldaps?://[\S]+\b`)
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"user", "bind"}) + `["']([a-zA-Z=,]{4,150})["']`)
	passwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pass"}) + `["']([\S]{4,48})["']`)
	iadPat      = regexp.MustCompile(`OpenDSObject\(\"(?i)(ldaps?://[\S]+)\", ?\"([\S]+)\", ?\"([\S]+)\",[ \d]+\)`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{
		[]byte("ldaps://"),
		[]byte("ldap://"),
	}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	uriMatches := uriPat.FindAllSubmatch(data, -1)
	for _, uri := range uriMatches {
		ldapURL, err := url.Parse(string(uri[0]))
		if err != nil {
			continue
		}

		usernameMatches := usernamePat.FindAllSubmatch(data, -1)
		for _, username := range usernameMatches {
			if len(username) != 2 {
				continue
			}

			passwordMatches := passwordPat.FindAllSubmatch(data, -1)
			for _, password := range passwordMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_LDAP,
					Raw:          []byte(strings.Join([]string{ldapURL.String(), string(username[1]), string(password[1])}, "\t")),
				}

				if verify {
					verificationErr := verifyLDAP(string(username[1]), string(password[1]), ldapURL)
					s1.Verified = verificationErr == nil
					if !isErrDeterminate(verificationErr) {
						s1.VerificationError = verificationErr
					}
				}

				results = append(results, s1)
			}
		}
	}

	// Check for matches for the IAD library format
	iadMatches := iadPat.FindAllSubmatch(data, -1)
	for _, iad := range iadMatches {
		uri := iad[1]
		username := iad[2]
		password := iad[3]

		ldapURL, err := url.Parse(string(uri))
		if err != nil {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LDAP,
			Raw:          []byte(strings.Join([]string{ldapURL.String(), string(username), string(password)}, "\t")),
		}

		if verify {
			verificationError := verifyLDAP(string(username), string(password), ldapURL)

			s1.Verified = verificationError == nil
			if !isErrDeterminate(verificationError) {
				s1.VerificationError = verificationError
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func isErrDeterminate(err error) bool {
	switch e := err.(type) {
	case *ldap.Error:
		switch e.Err.(type) {
		case *net.OpError:
			return false
		}
	}

	return true
}

func verifyLDAP(username, password string, ldapURL *url.URL) error {
	// Tests with non-TLS, TLS, and STARTTLS

	ldap.DefaultTimeout = 5 * time.Second

	uri := ldapURL.String()

	switch ldapURL.Scheme {
	case "ldap":
		// Non-TLS dial
		l, err := ldap.DialURL(uri)
		if err != nil {
			return err
		}
		defer l.Close()
		// Non-TLS verify
		err = l.Bind(username, password)
		if err == nil {
			return nil
		}

		// STARTTLS
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		// STARTTLS verify
		return l.Bind(username, password)
	case "ldaps":
		// TLS dial
		l, err := ldap.DialTLS("tcp", uri, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		defer l.Close()
		// TLS verify
		return l.Bind(username, password)
	}

	return fmt.Errorf("unknown ldap scheme %q", ldapURL.Scheme)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LDAP
}
