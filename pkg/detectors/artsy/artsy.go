package artsy

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"artsy"}) + `\b([0-9a-zA-Z]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"artsy"}) + `\b([0-9a-zA-Z]{20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"artsy"}
}

// FromData will find and optionally verify Artsy secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idmatches {
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Artsy,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				isVerified, err := verifyMatch(ctx, client, resIdMatch, resMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(err, resMatch)
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, id, secret string) (bool, error) {
	// Reference: https://developers.artsy.net/v2/docs/authentication
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.artsy.net/api/tokens/xapp_token?client_id="+id+"&client_secret="+secret, http.NoBody)
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
	case http.StatusCreated:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Artsy
}

func (s Scanner) Description() string {
	return "Artsy is an online platform for discovering, buying, and selling art. Artsy API keys can be used to access Artsy's services and data."
}
