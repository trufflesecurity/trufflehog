package jwt

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
		parsedToken, _, err := jwt.NewParser(jwt.WithPaddingAllowed()).ParseUnverified(match, claims)
		if err != nil {
			// we can skip a token that doesn't parse without any validation or verification
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
			var isVerified bool
			var verificationErr error
			switch parsedToken.Method.Alg() {
			case "HS256", "HS384", "HS512":
				isVerified, verificationErr = verifyHMAC(parsedToken)
			default:
				isVerified, verificationErr = verifyPublicKey(ctx, client, match)
			}
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

// Attempt to verify a JWT that uses an HMAC algorithm.
//
// This implementation only attempts to verify JWTs whose issuers use the OIDC Discovery protocol to make public keys available via request.
func verifyHMAC(parsedToken *jwt.Token) (bool, error) {
	v := jwt.NewValidator(
		jwt.WithValidMethods([]string{
			jwt.SigningMethodHS256.Alg(),
			jwt.SigningMethodHS384.Alg(),
			jwt.SigningMethodHS512.Alg(),
		}),
		jwt.WithIssuedAt(),
		jwt.WithPaddingAllowed(),
		jwt.WithLeeway(time.Minute),
	)
	if err := v.Validate(parsedToken.Claims); err != nil {
		// though we have not checked the signature, the token is definitely invalid
		return false, nil
	}
	// If we return an error here, the finding will have `unknown` status.
	// Instead, let's treat HMAC-type JWTs (which we cannot verify in general) as `unverified`.
	// return false, fmt.Errorf("no key available to verify an HMAC-based signature")
	return false, nil
}

// Wrap an `io.Reader` with a reasonable limit as an additional measure against DoS from a malicious JWKS issuer
func limitReader(reader io.Reader) io.Reader {
	return io.LimitReader(reader, 1024*1024)
}

// Attempt to verify a JWT that uses a public-key signing algorithm.
//
// This implementation only attempts to verify JWTs whose issuers use the OIDC Discovery protocol to make public keys available via request.
func verifyPublicKey(ctx context.Context, client *http.Client, tokenString string) (bool, error) {

	// A key retrieval function that uses the OIDC Discovery protocol,
	// being careful to avoid possible DoS from a potentially malicious JWKS server.
	oidcDiscoveryKeyFunc := func(unverifiedToken *jwt.Token) (any, error) {
		issuer, err := unverifiedToken.Claims.GetIssuer()
		if err != nil {
			return nil, fmt.Errorf("invalid issuer: %w", err)
		}
		if issuer == "" {
			return nil, fmt.Errorf("missing issuer")
		}
		issuerURL, err := parseRoutableHttpsUrl(issuer)
		if err != nil {
			return nil, fmt.Errorf("unsupported issuer: %w: %q", err, issuer)
		}

		oidcDiscoveryURL := issuerURL.JoinPath(".well-known/openid-configuration")

		// Check for a proper key id before making any network requests
		kid, ok := unverifiedToken.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid key id")
		}

		// Fetch the OIDC discovery document
		resp, err := performHttpRequest(ctx, client, "GET", oidcDiscoveryURL.String())
		if err != nil {
			return nil, fmt.Errorf("failed to perform OIDC discovery: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("bad status for OIDC discovery document: %v", resp.Status)
		}

		// Get the JWKS URL from the OIDC discovery document
		var discoveryDoc struct {
			JWKSUri string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(limitReader(resp.Body)).Decode(&discoveryDoc); err != nil {
			return nil, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
		}

		jwksURL, err := parseRoutableHttpsUrl(discoveryDoc.JWKSUri)
		if err != nil {
			return nil, fmt.Errorf("invalid JWKS URL: %w", err)
		}

		if jwksURL.Host != issuerURL.Host {
			return nil, fmt.Errorf("JWKS host does not match issuer host: %q", discoveryDoc.JWKSUri)
		}

		// Fetch the JWKS
		resp, err = performHttpRequest(ctx, client, "GET", discoveryDoc.JWKSUri)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("bad status for JWKS: %v", resp.Status)
		}

		// Parse the JWKS and find the first matching key
		keySet, err := jwk.ParseReader(limitReader(resp.Body))
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWKS: %w", err)
		}
		matchingKey, found := keySet.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("no matching JWKS key")
		}

		// Parse matching key to the "raw" key type needed for signature verification
		var rawMatchingKey any
		err = jwk.Export(matchingKey, &rawMatchingKey)
		if err != nil {
			return nil, fmt.Errorf("failed to export matching key: %w", err)
		}

		return rawMatchingKey, nil
	}

	token, err := jwt.Parse(
		tokenString,
		oidcDiscoveryKeyFunc,
		jwt.WithValidMethods([]string{
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
	)
	switch {
	case token.Valid:
		return true, nil
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return false, err
	case errors.Is(err, jwt.ErrHashUnavailable):
		return false, err
	default:
		return false, nil
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JWT
}

func (s Scanner) Description() string {
	return "A JSON Web Token (JWT) is an approach to authentication or authorization that does not depend on server-side data. It may allow access to protected resources."
}
