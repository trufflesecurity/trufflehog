package signable

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

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

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	tokenPat   = regexp.MustCompile(detectors.PrefixRegex([]string{".{0,2}signable"}) + `\b([a-zA-Z-0-9]{32})\b`)
	keywordPat = regexp.MustCompile(`(?i)([a-z]{2})signable`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"signable"}
}

// FromData will find and optionally verify Signable secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := tokenPat.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		if isCommonFalsePositive(match[0]) {
			continue
		}

		resMatch := strings.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Signable,
			Raw:          []byte(resMatch),
		}

		if verify {
			if s.client == nil {
				s.client = defaultClient
			}
			isVerified, verificationErr := verifyResult(ctx, s.client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

// Eliminate the most common false positive.
func isCommonFalsePositive(line string) bool {
	// TODO: Skip lock files altogether. (https://github.com/trufflesecurity/trufflehog/issues/1517)
	if strings.Contains(line, "helper-explode-assignable-expression") {
		return true
	}

	// Eliminate false positives from `assignable` and `designable`.
	for _, m := range keywordPat.FindAllStringSubmatch(line, -1) {
		if strings.EqualFold(m[1], "as") || strings.EqualFold(m[1], "de") {
			return true
		}
	}
	return false
}

func verifyResult(ctx context.Context, client *http.Client, token string) (bool, error) {
	data := fmt.Sprintf("%s:", token)
	sEnc := b64.StdEncoding.EncodeToString([]byte(data))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.signable.co.uk/v1/templates?offset=0&limit=5", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return true, nil
	}
	return false, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Signable
}
