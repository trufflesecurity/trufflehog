package difydataset

import (
	"cmp"
	"context"
	"fmt"
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
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

// CloudEndpoint returns Dify Cloud's API host. Dify is open source and often
// self-hosted; a key from a self-hosted instance is unknown to Dify Cloud, so
// such instances are verified only when an operator configures their URL as a
// custom verification endpoint.
func (Scanner) CloudEndpoint() string { return "https://api.dify.ai" }

const keyPrefix = "dataset-"

var (
	defaultClient = common.SaneHttpClient()

	// dataset-<24 alphanumeric chars>, e.g. dataset-t8IMtmhWzulciBpTMRMTqwa4
	keyPat = regexp.MustCompile(`\b(dataset-[a-zA-Z0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{keyPrefix}
}

// FromData will find and optionally verify Dify Knowledge Base (dataset) API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_DifyDataset,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.VerificationClient(cmp.Or(s.client, defaultClient))

			// Verification targets Dify Cloud plus any operator-configured
			// endpoints, such as self-hosted instances. URLs found in the
			// scanned data are never called. Only non-nil errors overwrite
			// lastErr so that a clean 401 from one instance does not erase a
			// transient failure from an instance that might be authoritative.
			var lastErr error
			for _, baseURL := range s.Endpoints() {
				isVerified, vErr := verifyMatch(ctx, client, baseURL, match)
				s1.Verified = isVerified
				if vErr != nil {
					lastErr = vErr
				}
				if isVerified {
					lastErr = nil
					s1.ExtraData = map[string]string{"endpoint": baseURL}
					break
				}
			}
			s1.SetVerificationError(lastErr, match)
		}

		results = append(results, s1)
	}

	return results, nil
}

// datasetsURL builds the knowledge-base list URL for a Dify instance. Dify
// documents its API base as <host>/v1, so a configured endpoint may be given
// with or without the /v1 suffix.
func datasetsURL(baseURL string) (string, error) {
	base := strings.TrimSuffix(strings.TrimRight(baseURL, "/"), "/v1")
	return url.JoinPath(base, "/v1/datasets")
}

func verifyMatch(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	endpoint, err := datasetsURL(baseURL)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

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
		// Determinate success: key is live and can list the account's knowledge bases.
		return true, nil
	case http.StatusUnauthorized:
		// Determinate failure: this instance does not recognize the key.
		return false, nil
	case http.StatusForbidden:
		// Ambiguous: Dify answers a bad key with 401. A 403 can come from a
		// workspace or permission problem, or from a proxy in front of the
		// instance, while the key itself is still valid.
		return false, fmt.Errorf("forbidden response (HTTP 403): key validity could not be determined")
	default:
		// Indeterminate: unexpected status (rate limit, 5xx, etc).
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// IsFalsePositive runs the default false-positive check on the random part of
// the key only. The fixed dataset- prefix contains the dictionary word "data",
// so checking the whole key would discard every unverified Dify key.
func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	body := strings.TrimPrefix(string(result.Raw), keyPrefix)
	return detectors.IsKnownFalsePositive(body, detectors.DefaultFalsePositives, true)
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_DifyDataset
}

func (s Scanner) Description() string {
	return "Dify is an LLM app development platform. This is a Dify Knowledge Base API key (also called a dataset key), which grants access to every knowledge base visible to the account that created it, so a leaked key has a broad blast radius."
}
