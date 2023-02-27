package ldap

import (
	"context"
	"crypto/tls"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	uriPat = regexp.MustCompile(`\b(?i)ldaps?://[\S]+\b`)
	// ldap://127.0.0.1:389
	// ldap://127.0.0.1
	// ldap://mydomain.test
	// ldaps://[fe80:4049:92ff:fe44:4bd1]:5060
	// ldap://[fe80::4bd1]:5060
	// ldap://ds.example.com:389/dc=example,dc=com?givenName,sn,cn?sub?(uid=john.doe)
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"user", "bind"}) + `["']([a-zA-Z=,]{4,150})["']`)
	passwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pass"}) + `["']([\S]{4,48})["']`)

	// https://learn.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadsopendsobject-opendsobject?redirectedfrom=MSDN
	// I.E. Set ou = dso.OpenDSObject("LDAP://DC.business.com/OU=IT,DC=Business,DC=com", "Business\administrator", "Pa$$word01", 1)
	iadPat = regexp.MustCompile(`OpenDSObject\(\"(?i)(ldaps?://[\S]+)\", ?\"([\S]+)\", ?\"([\S]+)\",[ \d]+\)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ldaps://", "ldap://"}
}

// FromData will find and optionally verify Ldap secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Check for matches in the URI + username + password format
	uriMatches := uriPat.FindAllString(dataStr, -1)
	for _, uri := range uriMatches {
		ldapURL, err := url.Parse(uri)
		if err != nil {
			continue
		}

		usernameMatches := usernamePat.FindAllStringSubmatch(dataStr, -1)
		for _, username := range usernameMatches {
			passwordMatches := passwordPat.FindAllStringSubmatch(dataStr, -1)
			for _, password := range passwordMatches {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_LDAP,
					Raw:          []byte(strings.Join([]string{ldapURL.String(), username[1], password[1]}, "\t")),
				}

				if verify {
					s1.Verified = verifyLDAP(ctx, username[1], password[1], ldapURL)
				}

				results = append(results, s1)
			}
		}
	}

	// Check for matches for the IAD library format
	iadMatches := iadPat.FindAllStringSubmatch(dataStr, -1)
	for _, iad := range iadMatches {
		uri := iad[1]
		username := iad[2]
		password := iad[3]

		ldapURL, err := url.Parse(uri)
		if err != nil {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_LDAP,
			Raw:          []byte(strings.Join([]string{ldapURL.String(), username, password}, "\t")),
		}

		if verify {
			s1.Verified = verifyLDAP(ctx, username, password, ldapURL)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyLDAP(ctx context.Context, username, password string, ldapURL *url.URL) bool {
	// Tests with non-TLS, TLS, and STARTTLS

	ldap.DefaultTimeout = 5 * time.Second

	uri := ldapURL.String()

	switch ldapURL.Scheme {
	case "ldap":
		// Non-TLS dial
		l, err := ldap.DialURL(uri)
		if err == nil {
			defer l.Close()
			// Non-TLS verify
			err = l.Bind(username, password)
			if err == nil {
				return true
			}

			// STARTTLS
			err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err == nil {
				// STARTTLS verify
				err = l.Bind(username, password)
				if err == nil {
					return true
				}
			}
		}
	case "ldaps":
		// TLS dial
		l, err := ldap.DialTLS("tcp", uri, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			defer l.Close()
			// TLS verify
			err = l.Bind(username, password)
			if err == nil {
				return true
			}
		}
	}

	return false
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LDAP
}
