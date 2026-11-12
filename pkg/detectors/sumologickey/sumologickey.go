package sumologickey

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"

	regexp "github.com/wasilibs/go-re2"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var (
	_ detectors.Detector           = (*Scanner)(nil)
	_ detectors.EndpointCustomizer = (*Scanner)(nil)
)

var (
	defaultClient = common.SaneHttpClient()

	// Detect which instance the key is associated with.
	// https://help.sumologic.com/docs/api/getting-started/#documentation
	urlPat = regexp.MustCompile(`(?i)api\.(?:au|ca|de|eu|fed|jp|kr|in|us2)\.sumologic\.com`)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"sumo", "accessId"}) + `\b(su[A-Za-z0-9]{12})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sumo", "accessKey"}) + `\b([A-Za-z0-9]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sumo", "accessId", "accessKey"}
}

// CloudEndpoint is the US API endpoint. Endpoints are full URLs so that
// configured verifier endpoints, which may carry a path prefix, are used as
// given.
func (Scanner) CloudEndpoint() string { return "https://api.sumologic.com" }

// FromData will find and optionally verify SumoLogicKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := make(map[string]struct{})
	for _, match := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[match[1]] = struct{}{}
	}
	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[match[1]] = struct{}{}
	}
	hostMatches := make(map[string]struct{})
	for _, match := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		hostMatches[match[0]] = struct{}{}
	}
	foundEndpoints := make([]string, 0, len(hostMatches))
	for host := range hostMatches {
		foundEndpoints = append(foundEndpoints, "https://"+host)
	}

	// RawV2 identifies the secret, so it is built only from what the data
	// says and never from the verification outcome. Otherwise the same key
	// gets a different identity when it flips between verified and
	// unverified (for example when it is revoked), and consumers that dedupe
	// on RawV2 record it as a new secret. The access ID and regional host are
	// included only when the data names exactly one of each. The host is kept
	// bare (no scheme) because existing identities were recorded that way.
	rawV2Id := soleKey(idMatches)
	rawV2URL := soleKey(hostMatches)

	for accessKey := range keyMatches {
		var (
			verified         bool
			verifiedId       string
			verifiedEndpoint string
			lastErr          error
		)

		if verify {
			client := s.VerificationClient(cmp.Or(s.client, defaultClient))

			// Endpoints applies the engine's endpoint configuration:
			// configured verifier endpoints, the US cloud endpoint, and
			// regional hosts found in the data, each only when enabled.
			//
			// Only non-nil errors overwrite lastErr so that a clean 401 from
			// the wrong region or access ID doesn't erase a failure (500,
			// timeout) from a pair that might be authoritative.
			endpoints := s.Endpoints(foundEndpoints...)
		verification:
			for id := range idMatches {
				for _, baseURL := range endpoints {
					isVerified, vErr := verifyMatch(ctx, client, baseURL, id, accessKey)
					if vErr != nil {
						lastErr = vErr
					}
					if isVerified {
						verified, verifiedId, verifiedEndpoint, lastErr = true, id, baseURL, nil
						break verification
					}
				}
			}
		}

		r := createResult(rawV2Id, accessKey, rawV2URL, verified, lastErr)
		// Which access ID and endpoint a key verified with are reported here
		// rather than in RawV2, so they don't affect the secret's identity.
		// RawV2 omits the access ID when the data names several, and keys
		// are managed by access ID, so triage needs it from here.
		if verified {
			r.ExtraData["access_id"] = verifiedId
			r.ExtraData["endpoint"] = verifiedEndpoint
		}
		results = append(results, *r)
	}

	return results, nil
}

// soleKey returns the only key in m, or "" when m has zero or several keys.
func soleKey(m map[string]struct{}) string {
	if len(m) != 1 {
		return ""
	}
	for k := range m {
		return k
	}
	return ""
}

func verifyMatch(ctx context.Context, client *http.Client, baseURL string, id string, key string) (bool, error) {
	endpoint, err := url.JoinPath(baseURL, "/api/v1/users")
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(id, key)
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
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func createResult(accessId string, accessKey string, endpoint string, verified bool, err error) *detectors.Result {
	r := &detectors.Result{
		DetectorType: detector_typepb.DetectorType_SumoLogicKey,
		Raw:          []byte(accessKey),
		SecretParts:  map[string]string{"key": accessKey},
		Verified:     verified,
		ExtraData: map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/sumologic/",
		},
	}
	r.SetVerificationError(err, accessKey)

	// |endpoint| and |accessId| won't be specified unless there's a confident match.
	if accessId != "" {
		var sb strings.Builder
		sb.WriteString(`{`)
		sb.WriteString(`"accessId":"` + accessId + `"`)
		sb.WriteString(`,"accessKey":"` + accessKey + `"`)
		if endpoint != "" {
			sb.WriteString(`,"url":"` + endpoint + `"`)
		}
		sb.WriteString(`}`)
		r.RawV2 = []byte(sb.String())
	}

	return r
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SumoLogicKey
}

func (s Scanner) Description() string {
	return "Sumo Logic is a cloud-based machine data analytics service. Sumo Logic keys can be used to access and manage data within the Sumo Logic platform."
}
