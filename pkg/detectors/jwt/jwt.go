package jwt

import (
	"context"
	// "encoding/base64"
	"encoding/json"
	"fmt"
	// "strings"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/url"

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

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{
		"ewogICJ0eXA",
		"ewogICJhbGc",
		"eyJ0eXAiOiJ",
		"eyJhbGciOiJ",
	}
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
		issuerURL, err := url.Parse(issuer)
		if err != nil {
			return nil, err
		}

		oidcDiscoveryURL := issuerURL.JoinPath(".well-known/openid-configuration")
		if oidcDiscoveryURL.Scheme != "https" {
			return nil, fmt.Errorf("unsupported OIDC discovery scheme %s (expected https)", oidcDiscoveryURL.Scheme)
		}

		// Check for a proper key id before making any network requests
		kid, ok := unverifiedToken.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing key id")
		}

		// Fetch the OIDC discovery document
		req, err := http.NewRequestWithContext(ctx, "GET", oidcDiscoveryURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC discovery request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("OIDC discovery document returned status: %v", resp.Status)
		}

		// Get the JWKS URL from the OIDC discovery document
		var discoveryDoc struct {
			JWKSUri string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&discoveryDoc); err != nil {
			return nil, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
		}

		jwksURL, err := url.Parse(discoveryDoc.JWKSUri)
		if err != nil {
			return nil, fmt.Errorf("invalid JWKS URL: %w", err)
		}
		if jwksURL.Scheme != "https" {
			return nil, fmt.Errorf("unsupported JWKS URL scheme %s (expected https)", jwksURL.Scheme)
		}

		if jwksURL.Host != issuerURL.Host {
			return nil, fmt.Errorf("JWKS URL host does not match issuer host: %v", discoveryDoc.JWKSUri)
		}

		// Fetch the JWKS
		req, err = http.NewRequestWithContext(ctx, "GET", discoveryDoc.JWKSUri, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS request: %w", err)
		}
		resp, err = client.Do(req)
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
		if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
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
