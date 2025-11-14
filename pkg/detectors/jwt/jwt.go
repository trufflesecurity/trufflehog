package jwt

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies expected interfaces at compile time.
var _ interface {
	detectors.Detector
	detectors.MaxSecretSizeProvider
} = (*Scanner)(nil)

var keyPat = regexp.MustCompile(`\b((?:eyJ|ewogIC|ewoid)[A-Za-z0-9_-]{12,}={0,2}\.(?:eyJ|ewo)[A-Za-z0-9_-]{12,}={0,2}\.[A-Za-z0-9_-]{12,})\b`)

// The default max secret size value for this detector must be overridden or JWTs with lots of claims will get missed.
func (s Scanner) MaxSecretSize() int64 {
	return 4096
}

// These keywords are derived from prefixes of the base64url-encoded versions of JSON object strings like the following:
//
// `{"typ":"`
// `{"alg":"`
// `{\n  "typ":"`
// `{\n    "typ":"`
func (s Scanner) Keywords() []string {
	return []string{
		"ewogIC",
		"ewoid",
		"eyJ",
	}
}

var jwtOptions = []jwt.ParserOption{
	jwt.WithValidMethods([]string{
		// HMAC-based algorithms
		// jwt.SigningMethodHS256.Alg(),
		// jwt.SigningMethodHS384.Alg(),
		// jwt.SigningMethodHS512.Alg(),

		// Public key-based algorithms
		jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodRS384.Alg(),
		jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodEdDSA.Alg(),
		jwt.SigningMethodES256.Alg(),
		jwt.SigningMethodES384.Alg(),
		jwt.SigningMethodES512.Alg(),
		jwt.SigningMethodPS256.Alg(),
		jwt.SigningMethodPS384.Alg(),
		jwt.SigningMethodPS512.Alg(),
	}),
	jwt.WithIssuedAt(),
	jwt.WithPaddingAllowed(),
	jwt.WithLeeway(time.Minute),
}

var jwtParser = jwt.NewParser(jwtOptions...)

var jwtValidator = jwt.NewValidator(jwtOptions...)

// FromData will find and optionally verify JWT secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	client := cmp.Or(s.client, common.SaneHttpClient())
	seenMatches := make(map[string]struct{})

	for _, matchGroups := range keyPat.FindAllStringSubmatch(string(data), -1) {
		match := matchGroups[1]

		if _, ok := seenMatches[match]; ok {
			continue
		}
		seenMatches[match] = struct{}{}

		claims := jwt.MapClaims{}
		parsedToken, tokenParts, err := jwtParser.ParseUnverified(match, claims)
		if err != nil || len(tokenParts) != 3 {
			// skip malformed tokens; no need to do claims validation or signature verification
			continue
		}

		switch parsedToken.Method.Alg() {
		case "HS256", "HS384", "HS512":
			// The JWT *might* be valid, but we can't in general do signature verification on HMAC-based algorithms.
			// We don't have a suitable status to represent this situation in trufflehog.
			// (The `unknown` status is intended to indicate that an error occurred to to external environment conditions, like trannsient network errors.)
			// So instead, to avoid possible false positives, totally skip HMAC-based JWTs; don't even create results for them.
			continue
		}

		// Decode signature
		parsedToken.Signature, err = jwtParser.DecodeSegment(tokenParts[2])
		if err != nil {
			// skip JWTs with malformed signatures
			continue
		}

		issString, _ := claims.GetIssuer()

		iatString := ""
		iat, err := claims.GetIssuedAt()
		if err == nil && iat != nil {
			iatString = iat.String()
		}

		expString := ""
		exp, err := claims.GetExpirationTime()
		if err == nil && exp != nil {
			expString = exp.String()
		}

		extraData := map[string]string{
			"alg": parsedToken.Method.Alg(),
			"iss": issString,
			"iat": iatString,
			"exp": expString,
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_JWT,
			Raw:          []byte(match),
			ExtraData:    extraData,
		}

		if verify {
			isVerified, verificationErr := verifyJWT(ctx, client, tokenParts, parsedToken)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

// Does the URL's refer to a non-routing host?
func isNonRoutingHost(url *url.URL) bool {
	h := url.Hostname()
	if h == "localhost" {
		return true
	}

	ip := net.ParseIP(h)
	if ip != nil {
		return ip.IsPrivate()
	}

	return false
}

// Parse a string into a URL, check that it is an HTTPS URL, and that it doesn't refer to a non-routing host.
func parseRoutableHttpsUrl(urlString string) (*url.URL, error) {
	url, err := url.ParseRequestURI(urlString)
	if err != nil {
		return nil, err
	}
	if url.Scheme != "https" {
		return nil, fmt.Errorf("only https scheme is supported")
	}
	if isNonRoutingHost(url) {
		return nil, fmt.Errorf("only public hosts are supported")
	}

	return url, nil
}

func performHttpRequest(ctx context.Context, client *http.Client, method string, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	return resp, nil
}

// Wrap an `io.Reader` with a reasonable limit as an additional measure against DoS from a malicious JWKS issuer
func limitReader(reader io.Reader) io.Reader {
	return io.LimitReader(reader, 1024*1024)
}

// Attempt to verify a JWT
//
// This cannot be done in general, but in a few special cases we can get definitive answers.
//
// In particular:
//
// - If the JWT uses public key cryptography and the OIDC Discovery protocol, we can fetch the public key and perform signature verification
// - In all cases, we can perform claims validation (e.g., checking expiration time) and sometimes get a definite answer that a JWT is *not* live
func verifyJWT(ctx context.Context, client *http.Client, tokenParts []string, parsedToken *jwt.Token) (bool, error) {
	if err := jwtValidator.Validate(parsedToken.Claims); err != nil {
		// though we have not checked the signature, the token is definitely invalid
		return false, nil
	}

	// Use the OIDC Discovery protocol to fetch the public signing key,
	// being careful to avoid possible DoS from a potentially malicious JWKS server.
	issuer, err := parsedToken.Claims.GetIssuer()
	if err != nil || issuer == "" {
		// missing or invalid issuer
		return false, nil
	}
	issuerURL, err := parseRoutableHttpsUrl(issuer)
	if err != nil {
		// unsupported issuer
		return false, nil
	}

	oidcDiscoveryURL := issuerURL.JoinPath(".well-known/openid-configuration")

	// Check for a proper key id before making any network requests
	kid, ok := parsedToken.Header["kid"].(string)
	if !ok {
		// invalid key id
		return false, nil
	}

	// Fetch the OIDC discovery document
	resp, err := performHttpRequest(ctx, client, "GET", oidcDiscoveryURL.String())
	if err != nil {
		return false, fmt.Errorf("failed to perform OIDC discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("bad status for OIDC discovery document: %v", resp.Status)
	}

	// Get the JWKS URL from the OIDC discovery document
	var discoveryDoc struct {
		JWKSUri string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(limitReader(resp.Body)).Decode(&discoveryDoc); err != nil {
		return false, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	jwksURL, err := parseRoutableHttpsUrl(discoveryDoc.JWKSUri)
	if err != nil {
		return false, fmt.Errorf("invalid JWKS URL: %w", err)
	}

	if jwksURL.Host != issuerURL.Host {
		return false, fmt.Errorf("JWKS host does not match issuer host: %q", discoveryDoc.JWKSUri)
	}

	// Fetch the JWKS
	resp, err = performHttpRequest(ctx, client, "GET", discoveryDoc.JWKSUri)
	if err != nil {
		return false, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("bad status for JWKS: %v", resp.Status)
	}

	// Parse the JWKS and find the first matching key
	keySet, err := jwk.ParseReader(limitReader(resp.Body))
	if err != nil {
		return false, fmt.Errorf("failed to parse JWKS: %w", err)
	}
	matchingKey, found := keySet.LookupKeyID(kid)
	if !found {
		return false, fmt.Errorf("no matching JWKS key")
	}

	// Parse matching key to the "raw" key type needed for signature verification
	var rawMatchingKey any
	err = jwk.Export(matchingKey, &rawMatchingKey)
	if err != nil {
		return false, fmt.Errorf("failed to export matching key: %w", err)
	}

	err = parsedToken.Method.Verify(strings.Join(tokenParts[0:2], "."), parsedToken.Signature, rawMatchingKey)
	if err != nil {
		// signature invalid
		return false, nil
	}

		// signature valid and claims check out
	return true, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JWT
}

func (s Scanner) Description() string {
	return "A JSON Web Token (JWT) is an approach to authentication or authorization that does not depend on server-side data. It may allow access to protected resources."
}
