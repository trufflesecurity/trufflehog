package apptivo

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"apptivo"}) + `\b([a-z0-9-]{36})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"apptivo"}) + `\b([a-zA-Z0-9-]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"apptivo"}
}

// FromData will find and optionally verify Apptivo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])
		for _, idMatch := range idMatches {
			resIdMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Apptivo,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				isVerified, err := verifyMatch(ctx, client, resMatch, resIdMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(err, resMatch, resIdMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, apiKey, accessKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.apptivo.com/app/dao/v6/leads?a=getConfigData&apiKey=%s&accessKey=%s", apiKey, accessKey), http.NoBody)
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

	switch res.StatusCode {
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		return strings.Contains(string(bodyBytes), `displayName`), nil
	default:
		return false, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Apptivo
}

func (s Scanner) Description() string {
	return "Apptivo is a cloud-based suite of business solutions, including CRM, project management, and more. Apptivo API keys can be used to access and manage these services programmatically."
}
