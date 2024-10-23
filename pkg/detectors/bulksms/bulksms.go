package bulksms

import (
	"context"
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

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bulksms"}) + `\b([a-zA-Z0-9!@#$%^&*()]{29})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"bulksms"}) + `\b([A-F0-9-]{37})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"bulksms"}
}

// FromData will find and optionally verify Bulksms secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)
	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)

	verifiedKeys := make(map[string]bool)
	verifiedIDs := make(map[string]bool)

	for _, idMatch := range idMatches {
		if len(idMatch) != 2 {
			continue
		}
		resIDMatch := strings.TrimSpace(idMatch[1])

		if verifiedIDs[resIDMatch] {
			continue
		}

		for _, keyMatch := range keyMatches {
			if len(keyMatch) != 2 {
				continue
			}
			resKeyMatch := strings.TrimSpace(keyMatch[1])

			if verifiedKeys[resKeyMatch] {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Bulksms,
				Raw:          []byte(resKeyMatch),
				RawV2:        []byte(resKeyMatch + resIDMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.bulksms.com/v1/messages", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(resIDMatch, resKeyMatch)
				res, err := client.Do(req)
				if err == nil {
					defer func() {
						_, _ = io.Copy(io.Discard, res.Body)
						_ = res.Body.Close()
					}()

					if res.StatusCode == http.StatusOK {
						s1.Verified = true
						// Mark both ID and key as verified
						verifiedIDs[resIDMatch] = true
						verifiedKeys[resKeyMatch] = true
						results = append(results, s1)
						break
					}
				} else {
					s1.SetVerificationError(err, resKeyMatch)
				}
			}
			results = append(results, s1)

		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bulksms
}

func (s Scanner) Description() string {
	return "BulkSMS is a service used for sending SMS messages in bulk. BulkSMS credentials can be used to access and send messages through the BulkSMS API."
}
