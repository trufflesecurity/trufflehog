package coinbase_waas

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/coinbase/waas-client-library-go/auth"
	"github.com/coinbase/waas-client-library-go/clients"
	v1clients "github.com/coinbase/waas-client-library-go/clients/v1"
	v1 "github.com/coinbase/waas-client-library-go/gen/go/coinbase/cloud/pools/v1"
	"github.com/google/uuid"
	"google.golang.org/api/googleapi"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Reference: https://docs.cloud.coinbase.com/waas/docs/auth
	keyNamePat = regexp.MustCompile(`(organizations\\*/\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\\*/apiKeys\\*/\w{8}-\w{4}-\w{4}-\w{4}-\w{12})`)
	privKeyPat = regexp.MustCompile(`(-----BEGIN EC(?:DSA)? PRIVATE KEY-----(?:\r|\n|\\+r|\\+n)(?:[a-zA-Z0-9+/]+={0,2}(?:\r|\n|\\+r|\\+n))+-----END EC(?:DSA)? PRIVATE KEY-----(?:\r|\n|\\+r|\\+n)?)`)

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
	return []string{"organizations", "apiKeys", "begin ec"}
}

// FromData will find and optionally verify CoinbaseWaaS secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyNameMatches := keyNamePat.FindAllStringSubmatch(dataStr, -1)
	privKeyMatches := privKeyPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyNameMatch := range keyNameMatches {
		resKeyNameMatch := nameReplacer.Replace(strings.TrimSpace(keyNameMatch[1]))

		for _, privKeyMatch := range privKeyMatches {
			resPrivKeyMatch := keyReplacer.Replace(strings.TrimSpace(privKeyMatch[1]))

			if !isValidECPrivateKey([]byte(resPrivKeyMatch)) {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CoinbaseWaaS,
				Raw:          []byte(resPrivKeyMatch),
				RawV2:        []byte(resKeyNameMatch + ":" + resPrivKeyMatch),
			}

			if verify {
				isVerified, verificationErr := s.verifyMatch(ctx, resKeyNameMatch, resPrivKeyMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resPrivKeyMatch)
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
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		return false
	}

	return true
}

func (s Scanner) verifyMatch(ctx context.Context, apiKeyName, privKey string) (bool, error) {
	authOpt := clients.WithAPIKey(&auth.APIKey{
		Name:       apiKeyName,
		PrivateKey: privKey,
	})
	clientOpt := clients.WithHTTPClient(s.client)
	client, err := v1clients.NewPoolServiceClient(ctx, authOpt, clientOpt)
	if err != nil {
		return false, err
	}

	// Lookup an arbitrary pool name that shouldn't exist.
	_, err = client.GetPool(ctx, &v1.GetPoolRequest{Name: uuid.New().String()})
	if err != nil {
		var apiErr *googleapi.Error
		if errors.As(err, &apiErr) {
			if apiErr.Code == 401 {
				// Invalid |Name| or |PrivateKey|
				return false, nil
			} else if apiErr.Code == 404 {
				// Valid |Name| and |PrivateKey| but the pool doesn't exist (expected).
				return true, nil
			}
		}
		// Unhandled error.
		return false, err
	}
	// In theory this will never happen, but it also indicates a valid key.
	return true, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CoinbaseWaaS
}
