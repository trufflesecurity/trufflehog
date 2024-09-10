package maxmindlicense

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b([a-zA-Z0-9]{6}_[a-zA-Z0-9]{29}_mmk)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"_mmk"}
}

func (Scanner) Version() int { return 2 }

// FromData will find and optionally verify MaxMindLicense secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, key := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[key[1]] = struct{}{}
	}

	for key := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_MaxMindLicense,
			Raw:          []byte(key),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/maxmind/",
				"version":        fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			verified, vErr := s.verify(ctx, client, key)
			r.Verified = verified
			r.SetVerificationError(vErr, key)
		}

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) verify(ctx context.Context, client *http.Client, key string) (bool, error) {
	data := url.Values{}
	data.Add("license_key", key)

	// https://dev.maxmind.com/license-key-validation-api
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "https://secret-scanning.maxmind.com/secrets/validate-license-key",
		strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}

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
	case http.StatusNoContent:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MaxMindLicense
}
