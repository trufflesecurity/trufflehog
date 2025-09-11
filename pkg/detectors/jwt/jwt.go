package jwt

import (
	"context"
	"io"
	// "encoding/base64"
	"encoding/json"
	"fmt"

	// "strings"
	"errors"
	"time"

	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b((?:eyJ|ewogIC)[A-Za-z0-9_-]{12,}\.ey[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,})\b`)
)

// The keywords for JWT detection are derived from prefixes of JWT header values with `typ` and `alg` values taken from the following:
//
//     typ: ['JWT', 'jwt']
//     alg: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']
//
// These were used to create JSON values for the header, using a few variations of whitespace and indentation, and then base64url-encoded.
func (s Scanner) Keywords() []string {
	return []string{
		"ewogICJ0eXA",
		"ewogICJhbGc",
		"eyJ0eXAiOiJ",
		"eyJhbGciOiJ",
	}
}

// Wrap an `io.Reader` with a reasonable limit as an additional measure against DoS from a malicious JWKS issuer
func limitReader(reader io.Reader) io.Reader {
	return io.LimitReader(reader, 1024 * 1024)
}

// FromData will find and optionally verify JWT secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_JWT,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

// Parse a string into a URL and check that it is an HTTPS URL.
// The `name` parameter is used only for producing an error message.
func parseHttpsUrl(name string, urlString string) (*url.URL, error) {
	url, err := url.Parse(urlString)
	if err != nil {
		return nil, err
	}
	if url.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme for %s URL (expected https)", name)
	} else {
		return url, nil
	}
}

func performHttpRequest(client *http.Client, ctx context.Context, method string, url string) (*http.Response, error) {
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

// Attempt to verify a JWT.
//
// This implementation only attempts to verify JWTs that use an asymmetric encryption algorithm,
// and only those whose issuers use the OIDC Discovery protocol to make public keys available via request.
func verifyMatch(ctx context.Context, client *http.Client, tokenString string) (bool, map[string]string, error) {

	// A key retrieval function that uses the OIDC Discovery protocol
	oidcDiscoveryKeyFunc := func(unverifiedToken *jwt.Token) (any, error) {
		issuer, ok := unverifiedToken.Header["iss"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid issuer")
		}
		issuerURL, err := parseHttpsUrl("issuer", issuer)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer URL: %w", err)
		}

		oidcDiscoveryURL := issuerURL.JoinPath(".well-known/openid-configuration")

		// Check for a proper key id before making any network requests
		kid, ok := unverifiedToken.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid key id")
		}

		// Fetch the OIDC discovery document
		resp, err := performHttpRequest(client, ctx, "GET", oidcDiscoveryURL.String())
		if err != nil {
			return nil, fmt.Errorf("failed to perform OIDC discovery: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("OIDC discovery document returned status: %v", resp.Status)
		}

		// Get the JWKS URL from the OIDC discovery document
		var discoveryDoc struct {
			JWKSUri string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(limitReader(resp.Body)).Decode(&discoveryDoc); err != nil {
			return nil, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
		}

		jwksURL, err := parseHttpsUrl("JWKS", discoveryDoc.JWKSUri)
		if err != nil {
			return nil, fmt.Errorf("invalid JWKS URL: %w", err)
		}

		if jwksURL.Host != issuerURL.Host {
			return nil, fmt.Errorf("JWKS URL host does not match issuer host: %v", discoveryDoc.JWKSUri)
		}

		// Fetch the JWKS
		resp, err = performHttpRequest(client, ctx, "GET", discoveryDoc.JWKSUri)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("JWKS returned status: %v", resp.Status)
		}

		// Load JWKS into `jwt.VerificationKeySet` or `jwt.VerificationKey` from JSON
		type Key map[string]any
		var jwks struct {
			Keys []Key `json:"keys"`
		}
		if err := json.NewDecoder(limitReader(resp.Body)).Decode(&jwks); err != nil {
			return nil, fmt.Errorf("failed to parse JWKS: %w", err)
		}
		var matchingKey Key = nil
		for _, key := range jwks.Keys {
			if key["kid"] == kid {
				matchingKey = key
			}
		}
		if matchingKey == nil {
			return nil, fmt.Errorf("did not find matching JWKS key")
		}

		return matchingKey, nil
	}

	token, err := jwt.Parse(
		tokenString,
		oidcDiscoveryKeyFunc,
		jwt.WithValidMethods([]string{
			jwt.SigningMethodRS256.Alg(),
			jwt.SigningMethodRS384.Alg(),
			jwt.SigningMethodRS512.Alg(),
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
		return true, nil, nil
	case errors.Is(err, jwt.ErrTokenMalformed) ||
		errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenExpired) ||
		errors.Is(err, jwt.ErrTokenNotValidYet):
		// Not a token / invalid signature / expired / not active yet
		return false, nil, nil
	default:
		return false, nil, err
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JWT
}

func (s Scanner) Description() string {
	return "A JSON Web Token (JWT) is an approach to authentication or authorization that does not depend on server-side data. It may allow access to authorized resources."
}
