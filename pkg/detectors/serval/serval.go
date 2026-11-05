package serval

import (
	"cmp"
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	// endpoints overrides regionEndpoints in tests.
	endpoints []string
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// regionEndpoints are the public API hosts of Serval's cloud regions. Regions
// are isolated, so a key issued in one is unknown to the other and every
// region must be tried before a key is called invalid.
var regionEndpoints = []string{
	"https://public.api.serval.com",
	"https://public.eu1.serval.com",
}

var (
	defaultClient = common.SaneHttpClient()

	// Serval API key secrets are svl_secret_<tag>_<43 base62 random><6 base62
	// CRC32 checksum>. The tag names the key type: pk public API, wk
	// self-hosted worker, mk Serval-managed worker.
	secretPat = regexp.MustCompile(`\b(svl_secret_(pk|wk|mk)_([0-9A-Za-z]{43})([0-9A-Za-z]{6}))\b`)

	// The client ID that pairs with a secret is the API key's UUID.
	idPat = regexp.MustCompile(detectors.PrefixRegex([]string{"serval", "client"}) +
		`\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)
)

var keyTypes = map[string]string{
	"pk": "public_api",
	"wk": "worker",
	"mk": "managed_worker",
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"svl_secret_"}
}

// FromData will find and optionally verify Serval API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	secrets := make(map[string]string)
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		tag, random, checksum := match[2], match[3], match[4]
		// A failed checksum means the match is not a Serval-issued secret.
		if secretChecksum(tag, random) != checksum {
			continue
		}
		secrets[match[1]] = tag
	}
	if len(secrets) == 0 {
		return nil, nil
	}

	ids := make(map[string]struct{})
	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		ids[strings.ToLower(match[1])] = struct{}{}
	}

	for secret, tag := range secrets {
		// Verification needs the client ID, so a secret found without one
		// is still reported, unverified.
		if len(ids) == 0 {
			results = append(results, detectors.Result{
				DetectorType: detector_typepb.DetectorType_Serval,
				Raw:          []byte(secret),
				SecretParts:  map[string]string{"client_secret": secret},
				ExtraData:    map[string]string{"key_type": keyTypes[tag]},
			})
			continue
		}

		for id := range ids {
			r := detectors.Result{
				DetectorType: detector_typepb.DetectorType_Serval,
				Raw:          []byte(secret),
				RawV2:        []byte(id + ":" + secret),
				SecretParts:  map[string]string{"client_id": id, "client_secret": secret},
				ExtraData:    map[string]string{"key_type": keyTypes[tag]},
			}

			// Only public API keys can exchange credentials at the public
			// token endpoint. It rejects worker keys with the same 401 as a
			// wrong secret, so verifying them would report live keys as
			// invalid.
			if verify && tag == "pk" {
				client := cmp.Or(s.client, defaultClient)
				endpoints := s.endpoints
				if len(endpoints) == 0 {
					endpoints = regionEndpoints
				}
				isVerified, endpoint, vErr := verifyInRegions(ctx, client, endpoints, id, secret)
				r.Verified = isVerified
				if isVerified {
					r.ExtraData["endpoint"] = endpoint
				}
				r.SetVerificationError(vErr, secret)
			}

			results = append(results, r)

			// A secret belongs to exactly one client ID, so once a pair
			// verifies, trying the remaining IDs only spends rate limit.
			if r.Verified {
				break
			}
		}
	}

	return results, nil
}

// secretChecksum mirrors Serval's issuer: CRC32 (IEEE) of "<tag>_<random>",
// written big-endian as six base62 digits.
func secretChecksum(tag, random string) string {
	sum := crc32.ChecksumIEEE([]byte(tag + "_" + random))
	out := make([]byte, 6)
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = base62Alphabet[sum%62]
		sum /= 62
	}
	return string(out)
}

// verifyInRegions tries each region until one verifies the key and returns
// the endpoint that did. A 401 from one region does not override an
// indeterminate error from another, since that region may own the key.
func verifyInRegions(ctx context.Context, client *http.Client, endpoints []string, id, secret string) (bool, string, error) {
	var lastErr error
	for _, endpoint := range endpoints {
		isVerified, err := verifyKey(ctx, client, endpoint, id, secret)
		if isVerified {
			return true, endpoint, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	return false, "", lastErr
}

// verifyKey exchanges the credentials for an access token with the OAuth2
// client credentials grant. The token in a successful response is discarded.
//
// The error is non-nil only when verification is indeterminate. Serval
// answers 401 for any unknown, revoked, expired or mismatched key; every
// other status (429 rate limit, 5xx) says nothing about the key.
func verifyKey(ctx context.Context, client *http.Client, baseURL, id, secret string) (bool, error) {
	endpoint, err := url.JoinPath(baseURL, "/v2/auth/token")
	if err != nil {
		return false, err
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	return detector_typepb.DetectorType_Serval
}

func (s Scanner) Description() string {
	return "Serval is a workflow automation platform for IT and security teams. API keys pair a client ID with a secret and can call the Serval public API or run self-hosted workers."
}
