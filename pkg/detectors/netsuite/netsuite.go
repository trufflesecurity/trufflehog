package netsuite

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider

	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	consumerKeyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"netsuite", "consumer", "key"}) + `\b([a-zA-Z0-9]{64})\b`)
	consumerSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"netsuite", "consumer", "secret"}) + `\b([a-zA-Z0-9]{64})\b`)

	tokenKeyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"netsuite", "token", "key"}) + `\b([a-zA-Z0-9]{64})\b`)
	tokenSecretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"netsuite", "token", "secret"}) + `\b([a-zA-Z0-9]{64})\b`)

	accountIDPat = regexp.MustCompile(detectors.PrefixRegex([]string{"netsuite", "account", "id"}) + `\b([a-zA-Z0-9-_]{6,15})\b`)
)

type credentialSet struct {
	consumerKey    string
	consumerSecret string
	tokenKey       string
	tokenSecret    string
	accountID      string
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"netsuite"}
}

// FromData will find and optionally verify Netsuite secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// // find for credentials
	consumerKeyMatches := trimUniqueMatches(consumerKeyPat.FindAllStringSubmatch(dataStr, -1))
	consumerSecretMatches := trimUniqueMatches(consumerSecretPat.FindAllStringSubmatch(dataStr, -1))
	tokenKeyMatches := trimUniqueMatches(tokenKeyPat.FindAllStringSubmatch(dataStr, -1))
	tokenSecretMatches := trimUniqueMatches(tokenSecretPat.FindAllStringSubmatch(dataStr, -1))
	accountIDMatches := trimUniqueMatches(accountIDPat.FindAllStringSubmatch(dataStr, -1))

	for consumerKey := range consumerKeyMatches {
		for consumerSecret := range consumerSecretMatches {
			for tokenKey := range tokenKeyMatches {
				for tokenSecret := range tokenSecretMatches {
					for accountID := range accountIDMatches {
						cs := credentialSet{
							consumerKey:    consumerKey,
							consumerSecret: consumerSecret,
							tokenKey:       tokenKey,
							tokenSecret:    tokenSecret,
							accountID:      accountID,
						}

						if !isUniqueKeys(cs) {
							continue
						}

						s1 := detectors.Result{
							DetectorType: detectorspb.DetectorType_Netsuite,
							Raw:          []byte(consumerKey),
							RawV2:        []byte(consumerKey + consumerSecret),
						}

						if verify {
							client := s.client
							if client == nil {
								client = defaultClient
							}

							isVerified, err := verifyCredentials(ctx,
								client,
								cs)
							s1.Verified = isVerified
							s1.SetVerificationError(err, consumerKey)
						}
						results = append(results, s1)
					}
				}
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Netsuite
}

func verifyCredentials(ctx context.Context, client *http.Client, cs credentialSet) (bool, error) {
	// for url, filter or replace underscore in accountID if needed and lower case the accountID
	urlAccountId := strings.ToLower(strings.Replace(cs.accountID, "_", "-", -1))

	baseUrl := "https://" + urlAccountId + ".suitetalk.api.netsuite.com"

	const path = "/services/rest/record/v1/metadata-catalog/check"

	// nonce generate
	nonce, err := netsuiteNonce(11)
	if err != nil {
		return false, err
	}

	signature := makeSignature(http.MethodGet, baseUrl, path, map[string]string{
		"consumer_key":     cs.consumerKey,
		"consumer_secret":  cs.consumerSecret,
		"token_id":         cs.tokenKey,
		"token_secret":     cs.tokenSecret,
		"signature_method": "HMAC-SHA256",
		"timestamp":        strconv.FormatInt(time.Now().Unix(), 10),
		"nonce":            nonce,
		"version":          "1.0",
		"realm":            cs.accountID,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseUrl+path, nil)

	if err != nil {
		return false, err
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", signature)

	// Make the request
	res, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return false, nil
		}
		return false, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		// 401 indicates unverified credentials
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func generateHMACSHA256(message, secret string) string {
	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write the message to it
	h.Write([]byte(message))

	// Get the resulting HMAC as a byte slice
	hash := h.Sum(nil)

	// Encode the byte slice to a hexadecimal string
	return base64.StdEncoding.EncodeToString(hash)
}

func makeSignature(method, baseUrl, path string, params map[string]string) string {
	baseString := method + "&" + url.QueryEscape(baseUrl+path) + "&" +
		url.QueryEscape("oauth_consumer_key="+url.QueryEscape(params["consumer_key"])+
			"&oauth_nonce="+url.QueryEscape(params["nonce"])+
			"&oauth_signature_method="+url.QueryEscape(params["signature_method"])+
			"&oauth_timestamp="+url.QueryEscape(params["timestamp"])+
			"&oauth_token="+url.QueryEscape(params["token_id"])+
			"&oauth_version="+url.QueryEscape(params["version"]))

	key := url.QueryEscape(params["consumer_secret"]) + "&" + url.QueryEscape(params["token_secret"])

	signature := generateHMACSHA256(baseString, key)

	return "OAuth" + " " + "realm=\"" + params["realm"] + "\"," +
		"oauth_consumer_key=\"" + params["consumer_key"] + "\"," +
		"oauth_token=\"" + params["token_id"] + "\"," +
		"oauth_signature_method=\"" + params["signature_method"] + "\"," +
		"oauth_timestamp=\"" + params["timestamp"] + "\"," +
		"oauth_nonce=\"" + params["nonce"] + "\"," +
		"oauth_version=\"" + params["version"] + "\"," +
		"oauth_signature=\"" + url.QueryEscape(signature) + "\""
}

func trimUniqueMatches(matches [][]string) (result map[string]struct{}) {
	result = make(map[string]struct{})
	for _, match := range matches {
		if len(match) > 0 {
			trimmedString := strings.TrimSpace(match[1])
			result[trimmedString] = struct{}{}
		}
	}
	return result
}

// Check if a credential set is unique, this is used to avoid duplicates.
func isUniqueKeys(cs credentialSet) bool {
	seen := make(map[string]struct{})
	credentials := []string{cs.consumerKey, cs.consumerSecret, cs.tokenKey, cs.tokenSecret, cs.accountID}

	for _, cred := range credentials {
		if _, exists := seen[cred]; exists {
			return false
		}
		seen[cred] = struct{}{}
	}
	return true
}

// return a random nonce of 'n' character long
func netsuiteNonce(n int) (string, error) {
	// Nonce provides a random nonce string.
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}
