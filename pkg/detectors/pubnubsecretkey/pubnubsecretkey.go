package pubnubsecretkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	pubPat = regexp.MustCompile(`\b(pub-c-[0-9a-z]{8}-[0-9a-z]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
	subPat = regexp.MustCompile(`\b(sub-c-[0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
	// sec-c- keys are base64-encoded UUIDs: exactly 48 base64 chars (no padding) after "sec-c-"
	secPat = regexp.MustCompile(`\b(sec-c-[A-Za-z0-9+/]{48})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"sec-c-"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	secMatches := secPat.FindAllStringSubmatch(dataStr, -1)
	if len(secMatches) == 0 {
		return nil, nil
	}

	pubMatches := pubPat.FindAllStringSubmatch(dataStr, -1)
	subMatches := subPat.FindAllStringSubmatch(dataStr, -1)

	for _, secMatch := range secMatches {
		resSec := strings.TrimSpace(secMatch[1])

		for _, pubMatch := range pubMatches {
			resPub := strings.TrimSpace(pubMatch[1])

			for _, subMatch := range subMatches {
				resSub := strings.TrimSpace(subMatch[1])

				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_PubNubSecretKey,
					Raw:          []byte(resSec),
					SecretParts: map[string]string{
						"secret_key":    resSec,
						"publish_key":   resPub,
						"subscribe_key": resSub,
					},
					RawV2: []byte(resPub + "/" + resSub + "/" + resSec),
				}

				if verify {
					client := s.getClient()
					isVerified, verificationErr := verifyPubNubSecret(ctx, client, resPub, resSub, resSec)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, resSec)
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// verifyPubNubSecret verifies a pub+sub+sec triple using the PAM v2 grant endpoint.
// Signature algorithm is sourced directly from the official PubNub Go SDK:
// - endpoints.go: createSignatureV2FromStrings
// - utils/string_utils.go: PreparePamParams, PamEncode, GetHmacSha256
func verifyPubNubSecret(ctx context.Context, client *http.Client, pubKey, subKey, secKey string) (bool, error) {
	path := "/v2/auth/grant/sub-key/" + subKey

	params := url.Values{}
	params.Set("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	params.Set("uuid", "trufflehog")

	sortedQuery := preparePamParams(params)

	// string-to-sign: method\npubKey\npath\nsortedQuery\nbody (empty for GET)
	stringToSign := "GET\n" + pubKey + "\n" + path + "\n" + sortedQuery + "\n"

	mac := hmac.New(sha256.New, []byte(secKey))
	mac.Write([]byte(stringToSign))
	rawSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	urlSafeSig := strings.NewReplacer("+", "-", "/", "_").Replace(rawSig)
	urlSafeSig = strings.TrimRight(urlSafeSig, "=")
	signature := "v2." + urlSafeSig

	reqURL := "https://pubsub.pubnub.com" + path + "?" + sortedQuery + "&signature=" + signature

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// preparePamParams sorts query parameters and applies PubNub PAM encoding.
// Matches PreparePamParams from the official PubNub Go SDK (utils/string_utils.go).
func preparePamParams(params url.Values) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		for _, v := range params[k] {
			parts = append(parts, k+"="+pamEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// pamEncode applies URL encoding with additional escaping required by PubNub PAM.
// Matches PamEncode from the official PubNub Go SDK (utils/string_utils.go).
func pamEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	replacer := strings.NewReplacer(
		"*", "%2A", "!", "%21", "'", "%27",
		"(", "%28", ")", "%29", "[", "%5B",
		"]", "%5D", "~", "%7E",
	)
	return replacer.Replace(encoded)
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_PubNubSecretKey
}

func (s Scanner) Description() string {
	return "PubNub is a real-time communication platform. A PubNub Secret Key is used with Access Manager (PAM) to sign requests and grant or revoke channel access permissions."
}
