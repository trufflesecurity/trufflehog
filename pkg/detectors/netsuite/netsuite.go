package netsuite

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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

	// find for credentials
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

func addOauthParam(builder *strings.Builder, key, value string) {
	builder.WriteString(key)
	builder.WriteString("=\"")
	builder.WriteString(value)
	builder.WriteString("\",")
}

func makeSignature(method, baseUrl, path string, params map[string]string) string {
	var paramsStringBuilder strings.Builder
	paramsStringBuilder.WriteString("oauth_consumer_key=" + url.QueryEscape(params["consumer_key"]))
	paramsStringBuilder.WriteString("&oauth_nonce=" + url.QueryEscape(params["nonce"]))
	paramsStringBuilder.WriteString("&oauth_signature_method=" + url.QueryEscape(params["signature_method"]))
	paramsStringBuilder.WriteString("&oauth_timestamp=" + url.QueryEscape(params["timestamp"]))
	paramsStringBuilder.WriteString("&oauth_token=" + url.QueryEscape(params["token_id"]))
	paramsStringBuilder.WriteString("&oauth_version=" + url.QueryEscape(params["version"]))

	var signatureBaseBuilder strings.Builder

	signatureBaseBuilder.WriteString(method)
	signatureBaseBuilder.WriteString("&")
	signatureBaseBuilder.WriteString(url.QueryEscape(baseUrl + path))
	signatureBaseBuilder.WriteString("&")
	signatureBaseBuilder.WriteString(url.QueryEscape(paramsStringBuilder.String()))

	key := url.QueryEscape(params["consumer_secret"]) + "&" + url.QueryEscape(params["token_secret"])

	signature := generateHMACSHA256(signatureBaseBuilder.String(), key)

	var authHeaderBuilder strings.Builder
	authHeaderBuilder.WriteString("OAuth")
	authHeaderBuilder.WriteString(" ")

	addOauthParam(&authHeaderBuilder, "realm", params["realm"])
	addOauthParam(&authHeaderBuilder, "oauth_consumer_key", params["consumer_key"])
	addOauthParam(&authHeaderBuilder, "oauth_token", params["token_id"])
	addOauthParam(&authHeaderBuilder, "oauth_signature_method", params["signature_method"])
	addOauthParam(&authHeaderBuilder, "oauth_timestamp", params["timestamp"])
	addOauthParam(&authHeaderBuilder, "oauth_nonce", params["nonce"])
	addOauthParam(&authHeaderBuilder, "oauth_version", params["version"])
	addOauthParam(&authHeaderBuilder, "oauth_signature", url.QueryEscape(signature))

	// remove trailing comma
	authHeader := authHeaderBuilder.String()
	authHeader = authHeader[:len(authHeader)-1]
	return authHeader
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

/*
To generate a nonce, we need to generate a random string of characters.
*/

var (
	charset = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	// maxUnbiasedUint32 is the largest multiple of len(charset) that fits in a uint32.
	// It's used to ensure unbiased sampling when selecting characters from the charset.
	maxUnbiasedUint32 = uint32((1<<32 - 1) - ((1<<32 - 1) % uint64(len(charset))))
)

func netsuiteNonce(n int) (string, error) {
	b := make([]byte, n)
	buf := make([]byte, 4)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		num := binary.BigEndian.Uint32(buf)
		if num < maxUnbiasedUint32 {
			b[i] = charset[num%uint32(len(charset))]
			i++
		}
	}
	return string(b), nil
}
