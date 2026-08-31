package enigma

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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"enigma"}) + `\b([a-zA-Z0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"enigma"}
}

// FromData will find and optionally verify Enigma secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Enigma,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			isVerified, verificationErr := verifyKey(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyKey checks an Enigma API key against the GraphQL endpoint.
//
// The query selects only `__typename`, which the GraphQL spec guarantees on
// every root type, so verification does not depend on Enigma's evolving schema
// or any specific entity id. Authentication is driven by the HTTP status code:
// 200 means the key is valid, 401 mean it is not.
//
// A 200 is additionally guarded by a JSON Content-Type check: server could return
// a 200 HTML block page, which we must not mistake for a live key.
func verifyKey(ctx context.Context, client *http.Client, key string) (bool, error) {
	payload := strings.NewReader(`{"query":"{ __typename }"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.enigma.com/graphql", payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-api-key", key)

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
		if contentType := res.Header.Get("Content-Type"); !strings.Contains(contentType, "application/json") {
			return false, fmt.Errorf("got HTTP 200 with unexpected Content-Type %q", contentType)
		}

		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Enigma
}

func (s Scanner) Description() string {
	return "Enigma is a business data intelligence platform. Enigma API keys grant access to comprehensive firmographic, legal, and identity datasets."
}
