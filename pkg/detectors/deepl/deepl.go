package deepl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

const (
	// DeepL returns HTTP 456 when a valid key has exceeded its quota.
	quotaExceededStatus = 456

	proUsageURL  = "https://api.deepl.com/v2/usage"
	freeUsageURL = "https://api-free.deepl.com/v2/usage"
	adminKeysURL = "https://api.deepl.com/v2/admin/developer-keys"
)

var (
	defaultClient = common.SaneHttpClient()

	// DeepL keys are UUIDs. Free keys append ":fx" and admin keys append ":adm".
	// https://developers.deepl.com/docs/getting-started/auth
	uuidBody = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

	// Suffixed keys are high-signal on their own.
	suffixedKeyPat = regexp.MustCompile(`\b(` + uuidBody + `:(?:[fF][xX]|[aA][dD][mM]))\b`)

	// Pro keys are plain UUIDs, so require a DeepL identifier nearby.
	proKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"deepl"}) + `\b(` + uuidBody + `)\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"deepl"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range suffixedKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}
	for _, match := range proKeyPat.FindAllStringSubmatch(dataStr, -1) {
		key := match[1]
		if hasSuffixedForm(uniqueMatches, key) {
			continue
		}
		uniqueMatches[key] = struct{}{}
	}

	for match := range uniqueMatches {
		uuidPart := uuidFromKey(match)
		if _, ok := detectors.UuidFalsePositives[detectors.FalsePositive(strings.ToLower(uuidPart))]; ok {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DeepL,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
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

	return results, nil
}

func hasSuffixedForm(matches map[string]struct{}, uuid string) bool {
	lowerUUID := strings.ToLower(uuid)
	for existing := range matches {
		lower := strings.ToLower(existing)
		if strings.HasPrefix(lower, lowerUUID+":") {
			return true
		}
	}
	return false
}

func uuidFromKey(key string) string {
	if i := strings.LastIndex(key, ":"); i >= 0 {
		return key[:i]
	}
	return key
}

func keyKind(key string) string {
	switch {
	case strings.HasSuffix(strings.ToLower(key), ":fx"):
		return "free"
	case strings.HasSuffix(strings.ToLower(key), ":adm"):
		return "admin"
	default:
		return "pro"
	}
}

func verifyURL(key string) string {
	switch keyKind(key) {
	case "free":
		return freeUsageURL
	case "admin":
		return adminKeysURL
	default:
		return proUsageURL
	}
}

type usageResponse struct {
	CharacterCount int64 `json:"character_count"`
	CharacterLimit int64 `json:"character_limit"`
}

func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL(key), http.NoBody)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "DeepL-Auth-Key "+key)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	extraData := map[string]string{"type": keyKind(key)}

	switch res.StatusCode {
	case http.StatusOK:
		if keyKind(key) != "admin" {
			var usage usageResponse
			if err := json.NewDecoder(res.Body).Decode(&usage); err != nil {
				return true, extraData, fmt.Errorf("failed to decode usage response: %w", err)
			}
			extraData["character_count"] = fmt.Sprintf("%d", usage.CharacterCount)
			extraData["character_limit"] = fmt.Sprintf("%d", usage.CharacterLimit)
		}
		return true, extraData, nil
	case quotaExceededStatus:
		// Determinate success: valid key that has exhausted its quota.
		return true, extraData, nil
	case http.StatusUnauthorized:
		// Determinate failure: key is invalid/revoked. No error object.
		return false, nil, nil
	case http.StatusForbidden:
		// 403 is overloaded:
		//   - invalid/revoked key, or a Pro key sent to the Free host
		//   - a live *scoped* developer key missing the usage scope
		//     https://developers.deepl.com/docs/admin/api-key-permissions
		// Free (:fx) and admin (:adm) keys cannot be scoped, so 403 is invalid
		// for those types. For unsuffixed Pro keys, a "Missing required scope"
		// body means the key authenticated.
		if keyKind(key) == "pro" && missingRequiredScope(res.Body) {
			extraData["scoped"] = "true"
			return true, extraData, nil
		}
		return false, nil, nil
	default:
		// Indeterminate: unexpected status (rate limit, 5xx, etc).
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func missingRequiredScope(body io.Reader) bool {
	var errBody struct {
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 4096)).Decode(&errBody); err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(errBody.Detail), "missing required scope")
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DeepL
}

func (s Scanner) Description() string {
	return "DeepL is a machine translation service. DeepL API keys can be used to translate text and documents and to manage account usage."
}
