package nuntiq

import (
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

// Scanner detects Nuntiq credentials: customer API keys (nuntiq_ck_), partner API keys (nuntiq_pk_)
// and rotation secrets (nuntiq_rs_). Format:
//
//	nuntiq_<kind>_<env>_<8 hex key id>_<43 base64url random><6 base62 checksum>
//
// The checksum is CRC32 (IEEE) of the random part in base62 (0-9A-Za-z, most significant digit
// first), so a match with a wrong checksum is not a Nuntiq credential and is dropped without a
// request.
type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// The trailing boundary is checked in code, so adjacent keys are all reported.
	keyPat = regexp.MustCompile(`\b(nuntiq_(ck|pk|rs)_(live|test|dev)_[0-9a-f]{8}_([A-Za-z0-9_-]{43})([0-9A-Za-z]{6}))`)

	// The API host per environment word in the key.
	hosts = map[string]string{
		"live": "api.apreceiving.com",
		"test": "test-api.apreceiving.com",
		"dev":  "dev-api.apreceiving.com",
	}
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// checksum is the 6-character base62 CRC32 (IEEE) of the random part.
func checksum(random string) string {
	n := crc32.ChecksumIEEE([]byte(random))
	out := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		out[i] = base62[n%62]
		n /= 62
	}
	return string(out)
}

func isKeyChar(c byte) bool {
	return c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func (s Scanner) Keywords() []string {
	return []string{"nuntiq_ck_", "nuntiq_pk_", "nuntiq_rs_"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Nuntiq credentials in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	seen := make(map[string]struct{})
	for _, idx := range keyPat.FindAllStringSubmatchIndex(dataStr, -1) {
		if end := idx[3]; end < len(dataStr) && isKeyChar(dataStr[end]) {
			continue
		}
		key := dataStr[idx[2]:idx[3]]
		kind := dataStr[idx[4]:idx[5]]
		env := dataStr[idx[6]:idx[7]]
		random := dataStr[idx[8]:idx[9]]
		sum := dataStr[idx[10]:idx[11]]

		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if checksum(random) != sum {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Nuntiq,
			Raw:          []byte(key),
			ExtraData: map[string]string{
				"kind":        kindName(kind),
				"environment": env,
			},
			SecretParts: map[string]string{"key": key},
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, s.getClient(), hosts[env], key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, key)
		}

		results = append(results, s1)
	}

	return results, nil
}

// IsFalsePositive skips the default word-list check: every reported match already carries a valid
// CRC32 checksum, and the key's own fixed parts would trip it (the environment word "test").
func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func kindName(k string) string {
	switch k {
	case "ck":
		return "customer_api_key"
	case "pk":
		return "partner_api_key"
	default:
		return "rotation_secret"
	}
}

// verifyMatch asks the key-check endpoint of the key's environment. It answers 200 with
// {"valid": bool, "kind": ..., "environment": ...} for every format-valid credential and returns
// nothing about the tenant or account.
func verifyMatch(ctx context.Context, client *http.Client, host, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/api/v1/key-check", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-API-Key", key)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
	var body struct {
		Valid *bool `json:"valid"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return false, fmt.Errorf("unexpected response body: %w", err)
	}
	if body.Valid == nil {
		return false, fmt.Errorf("unexpected response body: no valid field")
	}
	return *body.Valid, nil
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Nuntiq
}

func (s Scanner) Description() string {
	return "Nuntiq is an accounts payable invoice processing platform. Nuntiq API keys and rotation secrets give access to a tenant's invoice, supplier and payment data through the Nuntiq customer and partner APIs."
}
