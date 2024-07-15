package netsuite

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/exp/rand"

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

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"netsuite"}
}

// FromData will find and optionally verify Twitter secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// find for consumer key + secrets
	consumerKeyMatches := make(map[string]struct{})
	for _, match := range consumerKeyPat.FindAllStringSubmatch(dataStr, -1) {
		consumerKeyMatches[match[1]] = struct{}{}
	}
	consumerSecretMatches := make(map[string]struct{})
	for _, match := range consumerSecretPat.FindAllStringSubmatch(dataStr, -1) {
		consumerSecretMatches[match[1]] = struct{}{}
	}

	tokenKeyMatches := make(map[string]struct{})
	for _, match := range tokenKeyPat.FindAllStringSubmatch(dataStr, -1) {
		tokenKeyMatches[match[1]] = struct{}{}
	}

	tokenSecretMatches := make(map[string]struct{})
	for _, match := range tokenSecretPat.FindAllStringSubmatch(dataStr, -1) {
		tokenSecretMatches[match[1]] = struct{}{}
	}

	accountIDMatches := make(map[string]struct{})
	for _, match := range accountIDPat.FindAllStringSubmatch(dataStr, -1) {
		accountIDMatches[match[1]] = struct{}{}
	}

	for consumerKey := range consumerKeyMatches {
		for consumerSecret := range consumerSecretMatches {
			for tokenKey := range tokenKeyMatches {
				for tokenSecret := range tokenSecretMatches {
					for accountID := range accountIDMatches {
						// triming the credentials
						consumerKey := strings.TrimSpace(consumerKey)
						consumerSecret := strings.TrimSpace(consumerSecret)

						tokenKey := strings.TrimSpace(tokenKey)
						tokenSecret := strings.TrimSpace(tokenSecret)

						accountID := strings.TrimSpace(accountID)

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
								consumerKey,
								consumerSecret,
								tokenKey,
								tokenSecret,
								accountID)
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

func verifyCredentials(ctx context.Context, client *http.Client, consumerKey, consumerSecret, tokenKey, tokenSecret, accountID string) (bool, error) {

	nonceGenerator := NetsuiteNoncer{}

	baseUrl := "https://" + accountID + ".suitetalk.api.netsuite.com"
	url := baseUrl + "/services/rest/record/v1/metadata-catalog/check"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)

	if err != nil {
		log.Fatalf("Error creating request: %v", err)
		return false, err
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", makeSignature("GET", url, "/services/rest/record/v1/metadata-catalog/customer", map[string]string{
		"consumer_key":     consumerKey,
		"consumer_secret":  consumerSecret,
		"token_id":         tokenKey,
		"token_secret":     tokenSecret,
		"signature_method": "HMAC-SHA256",
		"timestamp":        strconv.FormatInt(time.Now().Unix(), 10),
		"nonce":            nonceGenerator.Nonce(),
		"version":          "1.0",
		"realm":            accountID,
	}))

	// Make the request
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		// 403 indicates lack of permission, but valid token (could be due to twitter free tier)
		return true, nil
	case http.StatusUnauthorized:
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

// NetsuiteNoncer reads 11 bytes from crypto/rand and
// returns those bytes as string
type NetsuiteNoncer struct{}

func (n NetsuiteNoncer) Nonce() string {

	// Nonce provides a random nonce string.
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, 11)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
