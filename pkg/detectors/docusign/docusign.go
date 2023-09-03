package docusign

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

type Response struct {
	AccessToken string `json:"access_token"`
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"integration", "id"}) + common.UUIDPattern)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"secret"}) + common.UUIDPattern)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("docusign")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	idMatches := idPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, idMatch := range idMatches {
		if len(idMatch) != 2 {
			continue
		}
		resIDMatch := bytes.TrimSpace(idMatch[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := bytes.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Docusign,
				Raw:          resIDMatch,
				Redacted:     string(resIDMatch),
				RawV2:        append(resIDMatch, resSecretMatch...),
			}

			if verify {
				req, _ := http.NewRequestWithContext(ctx, "POST", "https://account-d.docusign.com/oauth/token?grant_type=client_credentials", nil)
				encodedCredentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", resIDMatch, resSecretMatch)))

				req.Header.Add("Accept", "application/vnd.docusign+json; version=3")
				req.Header.Add("Authorization", "Basic "+string(encodedCredentials))
				res, _ := client.Do(req)

				verifiedBodyResponse, _ := common.ResponseContainsSubstring(res.Body, "ey")
				res.Body.Close()

				if res.StatusCode >= 200 && res.StatusCode < 300 && verifiedBodyResponse {
					s1.Verified = true
				} else {
					if detectors.IsKnownFalsePositive(resIDMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Docusign
}
