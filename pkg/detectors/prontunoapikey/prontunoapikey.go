package prontunoapikey

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	// verifyURL overrides defaultVerifyURL in tests.
	verifyURL string
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// GET /v1/usage is read-only and tells every key state apart. The API
// authenticates the key before it checks the route's scope, so:
//   - 200                        -> active Management or MCP key
//   - 403 with insufficient_scope -> active Sending or Receiving key
//   - 401                        -> unknown, revoked, expired or disabled key
const defaultVerifyURL = "https://api.prontuno.net/v1/usage"

var (
	defaultClient = common.SaneHttpClient()

	// Prontuno API keys are pno_sk_<key ID>_<64 hex secret><8 hex checksum>.
	// The key ID is a TypeID suffix: 26 lowercase Crockford base32
	// characters, the first one no higher than 7.
	keyPat = regexp.MustCompile(`\b(pno_sk_([0-7][0-9a-hjkmnp-tv-z]{25})_[0-9a-f]{64})([0-9a-f]{8})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pno_sk_"}
}

// FromData will find and optionally verify Prontuno API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Maps each key to its ID.
	keys := make(map[string]string)
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		body, keyID, checksum := match[1], match[2], match[3]
		// A failed checksum means the match is not a Prontuno-issued key.
		if keyChecksum(body) != checksum {
			continue
		}
		keys[body+checksum] = keyID
	}

	for key, keyID := range keys {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_ProntunoApiKey,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"key": key},
			// The dashboard and the API list keys by this ID.
			ExtraData: map[string]string{"key_id": "key_" + keyID},
		}

		if verify {
			client := cmp.Or(s.client, defaultClient)
			isVerified, access, vErr := verifyKey(ctx, client, cmp.Or(s.verifyURL, defaultVerifyURL), key)
			r.Verified = isVerified
			if isVerified {
				r.ExtraData["access"] = access
			}
			r.SetVerificationError(vErr, key)
		}

		results = append(results, r)
	}

	return results, nil
}

// keyChecksum mirrors Prontuno's issuer: CRC32 (IEEE) of everything before
// the checksum, written as eight lowercase hex digits.
func keyChecksum(body string) string {
	return fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(body)))
}

type errorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// verifyKey reports whether the key is live and, if so, how much access it
// has. The error is non-nil only when verification is indeterminate.
func verifyKey(ctx context.Context, client *http.Client, verifyURL, key string) (bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, http.NoBody)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Authorization", "Bearer "+key)

	res, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, "account-wide (Management or MCP key)", nil

	case http.StatusForbidden:
		// A Sending or Receiving key authenticates but may not read usage.
		// Any other 403 (the CDN in front of the API, for one) says nothing
		// about the key.
		var body errorResponse
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			return false, "", fmt.Errorf("failed to decode 403 response body: %w", err)
		}
		if body.Error.Code == "insufficient_scope" {
			return true, "restricted (Sending or Receiving key)", nil
		}
		return false, "", fmt.Errorf("unexpected 403 response with error code %q", body.Error.Code)

	case http.StatusUnauthorized:
		return false, "", nil

	default:
		return false, "", fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_ProntunoApiKey
}

func (s Scanner) Description() string {
	return "Prontuno is a transactional email service. Prontuno API keys can send email, read sent and inbound email, and, depending on the key type, manage domains, webhooks, suppressions, API keys and SMTP credentials."
}
