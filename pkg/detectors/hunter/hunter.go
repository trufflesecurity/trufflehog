package hunter

import (
	"context"
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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hunter"}) + `\b([a-z0-9_-]{40})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"hunter"}
}

// FromData will find and optionally verify Hunter secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Hunter,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			verified, verErr := verifyMatch(ctx, s.getClient(), resMatch)
			s1.Verified = verified
			s1.SetVerificationError(verErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyMatch reports whether the key authenticates. A nil error with
// verified=false means the key is definitively invalid; a non-nil error means
// verification was indeterminate (a transport failure or an unexpected status
// such as a 429 rate limit or a 5xx), so the finding must not be silently
// treated as a non-secret.
func verifyMatch(ctx context.Context, client *http.Client, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.hunter.io/v2/leads_lists?api_key="+key, nil)
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return true, nil
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		// Definitive: the credentials were rejected.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Hunter
}

func (s Scanner) Description() string {
	return "Hunter is a service that helps find and verify professional email addresses. Hunter API keys can be used to access and retrieve data from the Hunter service."
}
