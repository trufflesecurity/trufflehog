package billomat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"billomat"}) + `\b([0-9a-z]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"billomat"}) + `\b([0-9a-z]{1,})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"billomat"}
}

// FromData will find and optionally verify Billomat secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, idMatch := range idMatches {
			resId := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Billomat,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resId),
			}

			if verify {
				isVerified, verificationErr := verifyBillomat(ctx, client, resId, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Billomat
}

func (s Scanner) Description() string {
	return "Billomat is an online invoicing software. Billomat API keys can be used to access and manage invoices, clients, and other related data."
}

// docs: https://www.billomat.com/en/api/basics/authentication/
func verifyBillomat(ctx context.Context, client *http.Client, id, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.billomat.net/api/v2/clients/myself", id), nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-BillomatApiKey", key)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
