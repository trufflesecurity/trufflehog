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

// Compile-time interface check
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	pubPat = regexp.MustCompile(`\b(pub-c-[0-9a-z]{8}-[0-9a-z]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
	subPat = regexp.MustCompile(`\b(sub-c-[0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`)
	// sec-c- keys are base64-encoded UUIDs: exactly 48 base64 chars (no padding) after "sec-c-"
	secPat = regexp.MustCompile(`\b(sec-c-[A-Za-z0-9+/]{48})\b`)
)

// Keywords used for fast pre-filtering
func (s Scanner) Keywords() []string {
	return []string{"sec-c-"}
}

// FromData scans for PubNub Secret Keys and optionally verifies them.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	secIdxMatches := secPat.FindAllStringSubmatchIndex(dataStr, -1)
	if len(secIdxMatches) == 0 {
		return nil, nil
	}

	pubIdxMatches := pubPat.FindAllStringSubmatchIndex(dataStr, -1)
	subIdxMatches := subPat.FindAllStringSubmatchIndex(dataStr, -1)

	if len(pubIdxMatches) == 0 || len(subIdxMatches) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})

	for _, secIdx := range secIdxMatches {
		resSec := dataStr[secIdx[2]:secIdx[3]]
		resPub := nearestMatch(dataStr, pubIdxMatches, secIdx[2])
		resSub := nearestMatch(dataStr, subIdxMatches, secIdx[2])

		key := resPub + "/" + resSub + "/" + resSec
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_PubNubSecretKey,
			Raw:          []byte(resSec),
			SecretParts: map[string]string{
				"secret_key":    resSec,
				"publish_key":   resPub,
				"subscribe_key": resSub,
			},
			RawV2: []byte(key),
		}

		if verify {
			isVerified, verificationErr := verifyPubNubSecret(ctx, s.getClient(), resPub, resSub, resSec)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resSec)
		}

		results = append(results, s1)
	}

	return results, nil
}

// nearestMatch returns the capture group value whose start position is closest to pos,
// pairing each secret key with its most likely companion rather than a Cartesian product.
func nearestMatch(data string, matches [][]int, pos int) string {
	best := ""
	bestDist := -1
	for _, m := range matches {
		dist := m[2] - pos
		if dist < 0 {
			dist = -dist
		}
		if bestDist < 0 || dist < bestDist {
			bestDist = dist
			best = data[m[2]:m[3]]
		}
	}
	return best
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// verifyPubNubSecret verifies a pub+sub+sec triple using the PAM v2 audit endpoint.
// The audit endpoint is read-only, so verification does not mutate any Access Manager state.
// Signature algorithm sourced from the official PubNub Go SDK:
// - endpoints.go: createSignatureV2FromStrings
// - utils/string_utils.go: PreparePamParams, PamEncode, GetHmacSha256
func verifyPubNubSecret(ctx context.Context, client *http.Client, pubKey, subKey, secKey string) (bool, error) {
	path := "/v2/auth/audit/sub-key/" + subKey

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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
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
