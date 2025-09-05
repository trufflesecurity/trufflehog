package confluent

import (
	"context"
	b64 "encoding/base64"
	"fmt"
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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"confluent"}) + `\b([a-zA-Z0-9]{16})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"confluent"}) + `\b([a-zA-Z0-9\+\/]{64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"confluent"}
}

func (Scanner) Version() int { return 1 }

// FromData will find and optionally verify Confluent secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, secret := range secretMatches {
			resSecret := strings.TrimSpace(secret[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Confluent,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecret),
				ExtraData: map[string]string{
					"rotation_guide": "https://docs.confluent.io/cloud/current/security/authenticate/workload-identities/service-accounts/api-keys/best-practices-api-keys.html#rotate-api-keys-regularly",
					"version":        fmt.Sprintf("%d", s.Version()),
				},
			}

			if verify {
				data := fmt.Sprintf("%s:%s", resMatch, resSecret)
				sEnc := b64.StdEncoding.EncodeToString([]byte(data))
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.confluent.cloud/iam/v2/api-keys/"+resMatch, nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Confluent
}

func (s Scanner) Description() string {
	return "Confluent provides a streaming platform based on Apache Kafka to help companies harness their data in real-time. Confluent API keys can be used to access and manage Kafka clusters."
}
