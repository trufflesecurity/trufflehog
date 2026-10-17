package clickhouse

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

const (
	// ClickHouse's HTTP interface, which verification uses. The native protocol
	// ports below are what connection strings usually carry, so they get mapped
	// onto these.
	httpPort  = "8123"
	httpsPort = "8443"

	nativePort       = "9000"
	nativeSecurePort = "9440"

	// The user a connection string may omit, per ClickHouse's own default.
	defaultUser = "default"
)

var (
	defaultClient = common.SaneHttpClient()

	// Connection strings using ClickHouse's own scheme, which is what the Go,
	// Python and JDBC clients all accept: clickhouse://user:pass@host:9000/db
	// (clickhouses:// for TLS). Capture groups: user, password, host[:port], /database.
	keyPat = regexp.MustCompile(`\bclickhouses?://([^\s:/@]{0,64}):([^\s:/@]{3,100})@([-.\w]+(?::\d{1,5})?)(/[^\s?#"'` + "`" + `]*)?`)

	// ClickHouse Cloud speaks HTTPS rather than the native protocol, so its
	// credentials show up as ordinary basic-auth URLs. The domain is what makes
	// this unambiguous - a bare https:// URL with credentials is not a
	// ClickHouse finding. The host is captured whole and the domain checked in
	// code rather than pinned in the pattern, so that a longer hostname which
	// merely contains the domain (foo.clickhouse.cloud.example.com) is rejected
	// instead of being truncated to something we would then send a credential to.
	cloudPat = regexp.MustCompile(`\bhttps://([^\s:/@]{0,64}):([^\s:/@]{3,100})@([-\w.]+(?::\d{1,5})?)`)
)

const cloudDomain = ".clickhouse.cloud"

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"clickhouse"}
}

// FromData will find and optionally verify ClickHouse credentials in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)

	var results []detectors.Result
	seen := make(map[string]struct{})

	for _, m := range append(keyPat.FindAllStringSubmatch(dataStr, -1), cloudPat.FindAllStringSubmatch(dataStr, -1)...) {
		hostPort := m[3]
		isCloud := strings.HasPrefix(m[0], "https://")

		// Only ClickHouse Cloud hostnames are a ClickHouse finding in the HTTPS
		// form; any other host with basic-auth credentials belongs to something else.
		if isCloud && !isCloudHost(hostPort) {
			continue
		}

		// Userinfo in a URL is percent-encoded, so a password containing @, : or /
		// arrives here escaped. Sending the escaped form as the credential makes a
		// working password look invalid, so decode before using it anywhere.
		user, password := unescape(m[1]), unescape(m[2])
		if user == "" {
			user = defaultUser
		}

		// A password of only "*" is a redaction, and one starting with "$" is
		// almost always an unexpanded variable rather than a credential.
		if strings.Trim(password, "*") == "" || strings.HasPrefix(password, "$") {
			continue
		}

		var database string
		if len(m) > 4 {
			database = strings.TrimPrefix(m[4], "/")
		}

		secure := isCloud || strings.HasPrefix(m[0], "clickhouses://")

		// One result per distinct credential, not per occurrence.
		if _, ok := seen[user+"\x00"+password+"\x00"+hostPort]; ok {
			continue
		}
		seen[user+"\x00"+password+"\x00"+hostPort] = struct{}{}

		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_ClickHouse,
			Raw:          []byte(password),
			RawV2:        []byte(hostPort + user + password),
			// Redact the password as it was written, which may be the escaped form.
			Redacted: strings.ReplaceAll(m[0], m[2], "*******"),
			SecretParts: map[string]string{
				"host":     hostPort,
				"username": user,
				"password": password,
			},
			ExtraData: map[string]string{
				"host":     hostPort,
				"username": user,
			},
		}
		if database != "" {
			r.ExtraData["database"] = database
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			verified, verr := verifyClickHouse(ctx, client, hostPort, secure, user, password)
			r.Verified = verified
			r.SetVerificationError(verr, password)
		}

		results = append(results, r)
	}

	return results, nil
}

// unescape decodes percent-encoding from a URL userinfo field, leaving the value
// alone when it isn't validly encoded so that a password containing a bare % is
// still reported as written.
func unescape(s string) string {
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

// isCloudHost reports whether a host belongs to ClickHouse Cloud, matching on the
// domain rather than a substring so that a lookalike host is not accepted.
func isCloudHost(hostPort string) bool {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	return strings.HasSuffix(strings.ToLower(host), cloudDomain)
}

// httpEndpoint maps a connection string's host onto ClickHouse's HTTP interface.
//
// Verification goes over HTTP rather than the native protocol so that the
// detector needs no database driver. Connection strings normally carry a native
// port, so those are translated to the HTTP equivalent; a port that is neither
// is left alone, since some deployments publish the HTTP interface elsewhere.
// When the HTTP interface is not exposed the request simply fails, which is an
// indeterminate result rather than a claim that the credential is invalid.
func httpEndpoint(hostPort string, secure bool) string {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host, port = hostPort, ""
	}

	switch port {
	case nativeSecurePort, httpsPort:
		secure, port = true, httpsPort
	case nativePort, httpPort, "":
		if secure {
			port = httpsPort
		} else {
			port = httpPort
		}
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func verifyClickHouse(ctx context.Context, client *http.Client, hostPort string, secure bool, user, password string) (bool, error) {
	endpoint := httpEndpoint(hostPort, secure) + "/?query=" + url.QueryEscape("SELECT 1")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	// ClickHouse's own auth headers, which work on both the open-source HTTP
	// interface and Cloud, and avoid basic-auth encoding of exotic passwords.
	req.Header.Set("X-ClickHouse-User", user)
	req.Header.Set("X-ClickHouse-Key", password)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// The host comes from the connection string and an unrecognised port is used
	// as given, so the responder is not necessarily ClickHouse. Every ClickHouse
	// reply, success or auth failure, carries X-ClickHouse-* headers; without one
	// we cannot read anything into the status, so the result stays indeterminate
	// rather than verifying a credential against some unrelated web server.
	if !isClickHouseResponse(res.Header) {
		return false, fmt.Errorf("response from %s is not ClickHouse (status %d)", endpoint, res.StatusCode)
	}

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// ClickHouse answers AUTHENTICATION_FAILED with 403; either way the
		// server reached a decision, so this is a determinate failure.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func isClickHouseResponse(h http.Header) bool {
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Clickhouse-") {
			return true
		}
	}
	return false
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ClickHouse
}

func (s Scanner) Description() string {
	return "ClickHouse is a column-oriented database for online analytical processing. Credentials for a ClickHouse server or ClickHouse Cloud service allow reading and modifying the data it stores."
}
