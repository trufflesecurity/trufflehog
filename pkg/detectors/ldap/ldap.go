package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

func init() {
	ldap.DefaultTimeout = 5 * time.Second
}

var (
	// Basic patterns for individual credential components.
	// These are used when structured patterns don't match.

	// uriPat matches LDAP and LDAPS URIs.
	// Examples:
	//   ldap://127.0.0.1:389
	//   ldap://127.0.0.1
	//   ldap://mydomain.test
	//   ldaps://[fe80:4049:92ff:fe44:4bd1]:5060
	//   ldap://[fe80::4bd1]:5060
	//   ldap://ds.example.com:389/dc=example,dc=com?givenName,sn,cn?sub?(uid=john.doe)
	uriPat = regexp.MustCompile(`\b(?i)ldaps?://[\S]+\b`)

	// usernamePat matches common username patterns in configuration.
	usernamePat = regexp.MustCompile(detectors.PrefixRegex([]string{"user", "bind"}) + `["']([a-zA-Z=,]{4,150})["']`)

	// passwordPat matches password patterns with context.
	passwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pass"}) + `["']([\S]{4,48})["']`)

	// High-confidence patterns that capture complete credential sets.
	// These patterns have very low false positive rates.

	// iadPat matches Windows IAD/ADSI OpenDSObject calls.
	// https://learn.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadsopendsobject-opendsobject?redirectedfrom=MSDN
	// Example: Set ou = dso.OpenDSObject("LDAP://DC.business.com/OU=IT,DC=Business,DC=com", "Business\administrator", "Pa$$word01", 1)
	iadPat = regexp.MustCompile(`OpenDSObject\(\"(?i)(ldaps?://[\S]+)\", ?\"([\S]+)\", ?\"([\S]+)\",[ \d]+\)`)

	// configBlockPat matches common config file formats where credentials appear together.
	// This pattern is flexible but requires all three components in proximity.
	// Example:
	//   ldap://server.com
	//   user='cn=admin,dc=example,dc=com'
	//   password='secret'
	configBlockPat = regexp.MustCompile(`(?s)(?i)(ldaps?://[^\s"']+).*?(?:user|bind)[^"']*["']([^"'()]+)["'].*?pass[^"']*["']([^"']+)["']`)

	// connectionStringPat matches semicolon/comma-delimited connection strings.
	// Example: ldap://server.com;user=admin;pass=secret123
	connectionStringPat = regexp.MustCompile(`(?i)ldap://([^;,\s]+)[;,].*?user[=:]([^;,\s]+)[;,].*?pass[=:]([^;,\s]+)`)

	// yamlPat matches YAML-style LDAP configuration.
	// Example:
	//   ldap:
	//     url: ldaps://ldap.example.com
	//     bind_dn: "cn=admin,dc=example,dc=com"
	//     password: "secretpassword"
	yamlPat = regexp.MustCompile(`(?i)ldap:\s*\n\s*url:\s*(ldaps?://[^\s]+)\s*\n\s*bind_?dn:\s*"?([^\n"]+)"?\s*\n\s*password:\s*"?([^\n"]+)"?`)

	// envPat matches environment variable patterns.
	// Example:
	//   LDAP_URL=ldaps://ldap.example.com
	//   LDAP_BIND_DN=cn=service,dc=example,dc=com
	//   LDAP_PASSWORD=servicepass123
	envPat = regexp.MustCompile(`(?i)LDAP_URL=(ldaps?://[^\s]+).*?LDAP_BIND_DN=([^\s]+).*?LDAP_PASSWORD=([^\s]+)`)

	// High-confidence pattern processors.
	patterns = [...]struct {
		name    string
		pattern *regexp.Regexp
		extract func([]string) (uri, user, pass string)
	}{
		{
			name:    "IAD/ADSI",
			pattern: iadPat,
			extract: func(m []string) (string, string, string) { return m[1], m[2], m[3] },
		},
		{
			name:    "ConfigBlock",
			pattern: configBlockPat,
			extract: func(m []string) (string, string, string) { return m[1], m[2], m[3] },
		},
		{
			name:    "ConnectionString",
			pattern: connectionStringPat,
			extract: func(m []string) (string, string, string) {
				// Reconstruct full URI since pattern only captures hostname
				return "ldap://" + m[1], m[2], m[3]
			},
		},
		{
			name:    "YAML",
			pattern: yamlPat,
			extract: func(m []string) (string, string, string) { return m[1], m[2], m[3] },
		},
		{
			name:    "EnvironmentVariables",
			pattern: envPat,
			extract: func(m []string) (string, string, string) { return m[1], m[2], m[3] },
		},
	}
)

// Keywords returns a small set of substrings that quickly hint that an
// input might contain LDAP-related material.
//
// The surrounding scanner uses these keywords as a low-cost bloom filter
// before handing the file to this much heavier detector.
// The list is therefore intentionally minimal but distinctive.
func (s Scanner) Keywords() []string {
	return []string{"ldaps://", "ldap://"}
}

// createDeduplicationKey creates a normalized key for deduplication.
//
// The scanner purposely applies several families of regular expressions that can
// overlap:
//
//   - High-confidence, format-aware patterns ( iadPat, configBlockPat, … )
//   - The more generic proximity combinator that glues together individually
//     detected URI / user / password fragments.
//
// Both approaches can surface *the same* credential set, but not necessarily
// with identical strings – most notably the URI may differ in insignificant
// ways (casing, trailing slashes, explicit default ports, query strings, …).
//
// Example
//
//	# YAML-style config (matched by yamlPat)
//	url: LDAPS://directory.example.com
//
//	# Later in the same file an inline connection string (matched by
//	# connectionStringPat) refers to the very same server:
//	ldaps://directory.example.com:636;user=admin;pass=secret
//
// In both cases the credential triple is identical from a security point of
// view, yet string comparison would treat them as different unless the URI is
// normalized first.  By running the URI through url.Parse and serializing it
// back with .String() we collapse such cosmetic differences and are able to
// deduplicate results coming from different detection paths.
func createDeduplicationKey(uri, username, password string) string {
	if parsedURL, err := url.Parse(uri); err == nil {
		uri = parsedURL.String()
	}
	return strings.Join([]string{uri, username, password}, "\t")
}

// FromData searches the supplied byte slice for LDAP credential sets.
//
// The scan happens in two passes:
//
//  1. High-confidence regular expressions that match an entire
//     URI / username / password triple in a single shot.
//     These are cheap and precise and therefore executed first.
//
//  2. A proximity-based heuristic that first captures individual URIs,
//     usernames, and passwords and then stitches the nearest triples
//     together.  This pass is more expensive and may yield false
//     positives, so it is executed only after step 1.
//
// When verify is true the detector will attempt to bind to the discovered
// LDAP endpoint to confirm that the credentials are valid.  Verification
// is best-effort and may be skipped when the context is canceled.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Key format: "uri\tusername\tpassword"
	found := make(map[string]struct{})

	// 1. Process high-confidence patterns first (complete credential sets).
	highConfidenceResults := s.processHighConfidencePatterns(ctx, dataStr, found, verify)
	results = append(results, highConfidenceResults...)

	// 2. Process proximity-based combinations for any additional credentials.
	proximityResults := s.findProximityCombinations(ctx, data, found, verify)
	results = append(results, proximityResults...)

	return results, nil
}

// processHighConfidencePatterns handles patterns that capture complete credential sets.
// These patterns match specific configuration formats and have very low false positive rates.
func (s Scanner) processHighConfidencePatterns(ctx context.Context, dataStr string, found map[string]struct{}, verify bool) []detectors.Result {
	var results []detectors.Result

	for _, p := range patterns {
		matches := p.pattern.FindAllStringSubmatch(dataStr, -1)
		for _, match := range matches {
			select {
			case <-ctx.Done():
				return results
			default:
			}

			uri, user, pass := p.extract(match)
			credSet := CredentialSet{
				uri:      Match{value: uri},
				username: Match{value: user},
				pwd:      Match{value: pass},
				score:    0, // High confidence patterns get score 0
			}

			if result := s.createAndVerifyResult(ctx, credSet, verify); result != nil {
				key := createDeduplicationKey(uri, user, pass)
				if _, ok := found[key]; !ok {
					found[key] = struct{}{}
					results = append(results, *result)
				}
			}
		}
	}

	return results
}

// findProximityCombinations handles proximity-based matching logic
// The proximity combinator is the work-horse heuristic used once the
// cheaper "high-confidence" expressions have been exhausted.
// It deliberately limits the number of candidate triples evaluated
// (maxCombinations) to avoid pathological runtimes on large files.
func (s Scanner) findProximityCombinations(
	ctx context.Context,
	data []byte,
	found map[string]struct{},
	verify bool,
) []detectors.Result {
	var results []detectors.Result

	uris := findMatchesWithPosition(uriPat, data)
	usernames := findMatchesWithPosition(usernamePat, data)
	passwords := findMatchesWithPosition(passwordPat, data)

	// Skip if we don't have all components.
	if len(uris) == 0 || len(usernames) == 0 || len(passwords) == 0 {
		return results
	}

	// Find optimal combinations based on proximity.
	combinations := findOptimalCombinations(uris, usernames, passwords)

	for _, combo := range combinations {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		if result := s.createAndVerifyResult(ctx, combo, verify); result != nil {
			key := createDeduplicationKey(combo.uri.value, combo.username.value, combo.pwd.value)
			if _, ok := found[key]; !ok {
				found[key] = struct{}{}
				results = append(results, *result)

				if len(results) >= maxResults {
					break
				}
			}
		}
	}

	return results
}

// Match records a single regular-expression capture along with its byte
// offsets within the scanned text.
// It is used as a lightweight value object when computing proximity between
// the URI, username, and password fragments that may form an LDAP credential
// set.
type Match struct {
	// value holds the substring captured by the regular expression.
	value string

	// start is the starting byte offset of Value in the original byte slice.
	start int

	// end is the exclusive ending byte offset of Value in the original byte
	// slice.
	end int
}

// CredentialSet groups the three components—URI, username, and password—that
// together may constitute a valid LDAP credential discovered in source code.
// The zero value is not meaningful; instances are produced internally by
// findOptimalCombinations.
type CredentialSet struct {
	// uri is the LDAP endpoint captured from the scanned text.
	uri Match

	// username is the bind DN or simple username captured from the scanned
	// text.
	username Match

	// pwd is the credential associated with Username.
	pwd Match

	// score ranks this set by proximity; lower values indicate that the three
	// fragments were located nearer to each other in the source and therefore
	// have a higher likelihood of forming a real credential.
	score int
}

// Configuration constants.
const (
	// maxCombinations limits the number of proximity-based combinations to evaluate.
	// This prevents quadratic runtime on files with many potential matches.
	maxCombinations = 20

	// maxProximity is the maximum character distance between credential components
	// to consider them related. Larger values increase false positives.
	maxProximity = 200

	// maxResults is a safety limit for proximity combinations only.
	// High-confidence patterns are not subject to this limit.
	maxResults = 15
)

// findMatchesWithPosition finds all regex matches and returns their positions.
func findMatchesWithPosition(pattern *regexp.Regexp, data []byte) []Match {
	dataStr := string(data)
	matches := pattern.FindAllStringSubmatchIndex(dataStr, -1)
	var results []Match

	for _, match := range matches {
		if len(match) >= 4 { // Has capture group
			results = append(results, Match{
				value: dataStr[match[2]:match[3]],
				start: match[2],
				end:   match[3],
			})
		} else if len(match) >= 2 { // Full match only
			results = append(results, Match{
				value: dataStr[match[0]:match[1]],
				start: match[0],
				end:   match[1],
			})
		}
	}
	return results
}

// findOptimalCombinations finds the best credential combinations based on proximity.
func findOptimalCombinations(uris, usernames, passwords []Match) []CredentialSet {
	var combinations []CredentialSet

	for _, uri := range uris {
		for _, username := range usernames {
			for _, password := range passwords {
				score := calculateProximityScore(uri, username, password)

				// Skip combinations that are too far apart.
				if score > maxProximity {
					continue
				}

				combinations = append(combinations, CredentialSet{
					uri:      uri,
					username: username,
					pwd:      password,
					score:    score,
				})
			}
		}
	}

	// Sort by proximity score (lower is better).
	sort.Slice(combinations, func(i, j int) bool {
		return combinations[i].score < combinations[j].score
	})

	if len(combinations) > maxCombinations {
		combinations = combinations[:maxCombinations]
	}

	return combinations
}

// calculateProximityScore calculates how close together the credential components are.
func calculateProximityScore(uri, username, password Match) int {
	positions := []int{uri.start, uri.end, username.start, username.end, password.start, password.end}
	sort.Ints(positions)

	// Use the span from first to last position as the score.
	return positions[len(positions)-1] - positions[0]
}

// createAndVerifyResult creates and optionally verifies a detectors.Result.
func (s Scanner) createAndVerifyResult(ctx context.Context, credSet CredentialSet, verify bool) *detectors.Result {
	ldapURL, err := url.Parse(credSet.uri.value)
	if err != nil {
		return nil
	}

	result := detectors.Result{
		DetectorType: detectorspb.DetectorType_LDAP,
		Raw:          []byte(strings.Join([]string{ldapURL.String(), credSet.username.value, credSet.pwd.value}, "\t")),
	}

	if verify {
		select {
		case <-ctx.Done():
			return &result
		default:
		}

		verificationErr := verifyLDAP(credSet.username.value, credSet.pwd.value, ldapURL)
		result.Verified = verificationErr == nil
		if !isErrDeterminate(verificationErr) {
			result.SetVerificationError(verificationErr, credSet.pwd.value)
		}
	}

	return &result
}

// verifyLDAP performs the minimal set of network operations required to
// decide whether the credentials are valid:
//
//   - Plain LDAP   → Bind, optional STARTTLS + Bind
//   - LDAPS (TLS)  → Bind over an opportunistically insecure TLS config.
//
// We purposefully set InsecureSkipVerify because scanners very often run
// in environments where the target's certificate chain is not trusted.
// The objective is simply to confirm that the credentials *could* be
// used, not to validate the server's identity.
func verifyLDAP(username, password string, ldapURL *url.URL) error {
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
		l, err := ldap.DialURL(uri, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			return err
		}
		defer l.Close()
		// TLS verify
		return l.Bind(username, password)
	default:
		return fmt.Errorf("unknown ldap scheme %q", ldapURL.Scheme)
	}
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

// Type satisfies the detectors.Detector interface
// and returns the enumerated protobuf value that identifies
// this detector as the LDAP detector.
func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LDAP
}

// Description provides a human-readable explanation of what the detector
// looks for.
func (s Scanner) Description() string {
	return "LDAP (Lightweight Directory Access Protocol) is an open, vendor-neutral, industry standard application protocol for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network."
}
