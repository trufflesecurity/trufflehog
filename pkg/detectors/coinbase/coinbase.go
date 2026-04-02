package coinbase

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/golang-jwt/jwt/v5"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Reference: https://docs.cdp.coinbase.com/coinbase-app/docs/auth/api-key-authentication
	keyNamePat    = regexp.MustCompile(`\b(organizations\\*/\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\\*/apiKeys\\*/\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\b`)
	privateKeyPat = regexp.MustCompile(`(-----BEGIN EC(?:DSA)? PRIVATE KEY-----(?:\r|\n|\\+r|\\+n)(?:[a-zA-Z0-9+/]+={0,2}(?:\r|\n|\\+r|\\+n))+-----END EC(?:DSA)? PRIVATE KEY-----(?:\r|\n|\\+r|\\+n)?)`)

	apiHost              = "api.coinbase.com"
	verificationEndpoint = "/v2/user"
	verificationMethod   = http.MethodGet
	verificationURI      = fmt.Sprintf("https://%s%s", apiHost, verificationEndpoint)

	nameReplacer = strings.NewReplacer("\\", "")
	keyReplacer  = strings.NewReplacer(
		"\r\n", "\n",
		"\\r\\n", "\n",
		"\\n", "\n",
		"\\r", "\n",
	)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"begin ec"}
}

func isValidECPrivateKey(pemKey []byte) bool {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return false
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return false
	}

	// Check the key type
	_, ok := key.Public().(*ecdsa.PublicKey)
        return ok
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Coinbase secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeyNames, uniquePrivateKeys := map[string]struct{}{}, map[string]struct{}{}

	for _, keyNameMatch := range keyNamePat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeyNames[keyNameMatch[1]] = struct{}{}
	}

	for _, privateKeyMatch := range privateKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniquePrivateKeys[privateKeyMatch[1]] = struct{}{}
	}

	for keyName := range uniqueKeyNames {
		for privateKey := range uniquePrivateKeys {
			client := s.getClient()
			resKeyName := nameReplacer.Replace(strings.TrimSpace(keyName))
			resPrivateKey := keyReplacer.Replace(strings.TrimSpace(privateKey))

			if !isValidECPrivateKey([]byte(resPrivateKey)) {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Coinbase,
				Raw:          []byte(resPrivateKey),
				RawV2:        []byte(fmt.Sprintf("%s:%s", resKeyName, resPrivateKey)),
			}

			if verify {
				isVerified, verificationErr := s.verifyMatch(ctx, client, resKeyName, resPrivateKey)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resPrivateKey)
			}
			results = append(results, s1)

			// If we've found a verified match with this ID, we don't need to look for anymore. So move on to the next ID.
			if s1.Verified {
				break
			}

		}
	}

	return results, nil
}

func (s Scanner) verifyMatch(ctx context.Context, client *http.Client, keyName, privateKey string) (bool, error) {
	jwtToken, err := buildJWT(verificationMethod, apiHost, verificationEndpoint, keyName, privateKey)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, verificationMethod, verificationURI, http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}

// Coinbase API requires the credentials encoded in a JWT token
// The JWT token is signed with the private key and expires in 2 minutes
func buildJWT(method, host, endpoint, keyName, key string) (string, error) {
	// Decode the PEM key
	pemStr := strings.ReplaceAll(key, `\n`, "\n")
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return "", fmt.Errorf("failed to decode PEM block containing EC private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse EC private key: %v", err)
	}

	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"sub": keyName,
		"iss": "cdp",
		"nbf": now,
		"exp": now + 120,
		"uri": fmt.Sprintf("%s %s%s", method, host, endpoint),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyName
	token.Header["nonce"] = fmt.Sprintf("%x", makeNonce())

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %v", err)
	}

	return signedToken, nil
}

func makeNonce() []byte {
	nonce := make([]byte, 16) // 128-bit nonce
	_, _ = rand.Read(nonce)
	return nonce
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Coinbase
}

func (s Scanner) Description() string {
	return "Coinbase is a digital currency exchange that allows users to buy, sell, and store various cryptocurrencies. A Coinbase API key name and private key can be used to access and manage a user's account and transactions."
}
