package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ interface {
	detectors.Detector
	detectors.MaxSecretSizeProvider
} = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b((?:eyJ|ewogIC|ewoid)[A-Za-z0-9_-]{12,}={0,2}\.(?:eyJ|ewo)[A-Za-z0-9_-]{12,}={0,2}\.[A-Za-z0-9_-]{12,})\b`)
)

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

// Wrap an `io.Reader` with a reasonable limit as an additional measure against DoS from a malicious JWKS issuer
func limitReader(reader io.Reader) io.Reader {
	return io.LimitReader(reader, 1024*1024)
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
		issuerURL, err := parseHttpsUrl("issuer", issuer)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer URL %v: %w", issuer, err)
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
			return nil, fmt.Errorf("bad status for OIDC discovery document: %v", resp.Status)
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
		err = jwk.Export(matchingKey, &rawMatchingKey); if err != nil {
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
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return false, nil, err
	case errors.Is(err, jwt.ErrHashUnavailable):
		return false, nil, err
	default:
		return false, nil, nil
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JWT
}

func (s Scanner) Description() string {
	return "A JSON Web Token (JWT) is an approach to authentication or authorization that does not depend on server-side data. It may allow access to protected resources."
}
