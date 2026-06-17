package tly

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"tly"}) + `\b([0-9A-Za-z]{60})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"tly"}
}

// FromData will find and optionally verify TLy secrets in a given set of bytes.
func (s Scanner) FromData(
	ctx context.Context,
	verify bool,
	data []byte,
) (results []detectors.Result, err error) {

	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[strings.TrimSpace(match[1])] = struct{}{}
	}

	for key := range uniqueKeys {
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_TLy,
			Raw:          []byte(key),
			SecretParts: map[string]string{
				"key": key,
			},
		}

		if verify {
			verified, verificationErr := verifyTLyKey(ctx, client, key)
			result.SetVerificationError(verificationErr, key)
			result.Verified = verified
		}

		results = append(results, result)
	}

	return
}

func verifyTLyKey(
	ctx context.Context,
	client *http.Client,
	key string,
) (bool, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://api.t.ly/api/v1/link/list",
		http.NoBody,
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+key)
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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_TLy
}

func (s Scanner) Description() string {
	return "TLy is a URL shortening service. TLy API keys can be used to access and manage shortened URLs."
}
