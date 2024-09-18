package twitterconsumerkey

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"twitter", "consumer", "key"}) + `\b([a-zA-Z0-9]{25})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"twitter", "consumer", "secret"}) + `\b([a-zA-Z0-9]{50})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"twitter"}
}

// FromData will find and optionally verify Twitter secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// find for consumer key + secrets
	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[match[1]] = struct{}{}
	}
	secretMatches := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[match[1]] = struct{}{}
	}

	for key := range keyMatches {
		for secret := range secretMatches {
			key := strings.TrimSpace(key)
			secret := strings.TrimSpace(secret)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_TwitterConsumerkey,
				Raw:          []byte(key),
				RawV2:        []byte(key + secret),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				bearerToken, err := fetchBearerToken(ctx, client, key, secret)
				if err == nil {
					isVerified, err := verifyBearerToken(ctx, client, bearerToken)
					s1.Verified = isVerified
					s1.SetVerificationError(err, key)
				} else {
					s1.SetVerificationError(err, key)
				}
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TwitterConsumerkey
}

func verifyBearerToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twitter.com/2/tweets/20", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err == nil {
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

	return false, err
}

func fetchBearerToken(ctx context.Context, client *http.Client, key, secret string) (string, error) {
	payload := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.twitter.com/oauth2/token", payload)
	if err != nil {
		return "", err
	}
	sEnc := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", key, secret)))

	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		var token tokenResponse
		if err = json.NewDecoder(res.Body).Decode(&token); err != nil {
			return "", err
		}
		return token.AccessToken, nil
	default:
		return "", fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type tokenResponse struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
}
