package kenso

import (
	"cmp"
	"context"
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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

const (
	verifyURL = "https://api.ken.so/v1/me"
	// GET /v1/me is served only to API version 1.1. Without the Ken-Version
	// header the request is routed to the 1.0 API, which answers 404.
	kenVersion     = "1.1"
	base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	checksumLen    = 6
)

var (
	defaultClient = common.SaneHttpClient()

	// Kenso API keys are kenso_live_ (live) or kenso_test_ (sandbox), then 43
	// base62 characters, then a 6-character base62 CRC32 checksum.
	keyPat = regexp.MustCompile(`\b(kenso_(?:live|test)_[0-9A-Za-z]{49})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"kenso_live_", "kenso_test_"}
}

// FromData will find and optionally verify Kenso API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := match[1]
		// A failed checksum means the match is not a Kenso-issued key, so it
		// is neither reported nor sent for verification.
		if !checksumValid(key) {
			continue
		}
		uniqueMatches[key] = struct{}{}
	}

	for key := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Kenso,
			Raw:          []byte(key),
			SecretParts:  map[string]string{"key": key},
		}

		if verify {
			client := cmp.Or(s.client, defaultClient)
			isVerified, verificationErr := verifyKey(ctx, client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, key)
		}

		results = append(results, s1)
	}

	return results, nil
}

// checksumValid mirrors Kenso's issuer: the last 6 characters are the CRC32
// (IEEE) of everything before them, prefix included, written big-endian as
// base62 digits. The caller has already matched keyPat, so key is ASCII.
func checksumValid(key string) bool {
	head, tail := key[:len(key)-checksumLen], key[len(key)-checksumLen:]
	sum := crc32.ChecksumIEEE([]byte(head))
	out := make([]byte, checksumLen)
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = base62Alphabet[sum%62]
		sum /= 62
	}
	return string(out) == tail
}

// verifyKey calls a read-only endpoint that any valid key can read. The
// response body is discarded.
//
// The error is non-nil only when verification is indeterminate: Kenso answers
// 401 for any unknown or revoked key, and every other status says nothing
// about the key.
func verifyKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Ken-Version", kenVersion)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Kenso
}

func (s Scanner) Description() string {
	return "Kenso is an outbound sales platform for B2B cold email and LinkedIn campaigns. Kenso API keys authenticate requests to the Kenso API on behalf of a workspace and give access to its contacts and campaigns."
}
