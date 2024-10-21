package onesignal

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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"onesignal"}) + common.UUIDPattern)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"onesignal"}
}

// FromData will find and optionally verify Onesignal secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Onesignal,
			Raw:          []byte(resMatch),
		}

		if verify {
			data := fmt.Sprintf("%s:", resMatch)
			sEnc := b64.StdEncoding.EncodeToString([]byte(data))
			req, err := http.NewRequestWithContext(ctx, "GET", "https://onesignal.com/api/v1/apps", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.onesignal+json; version=3")
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Onesignal
}

func (s Scanner) Description() string {
	return "OneSignal is a customer engagement platform that enables businesses to send push notifications, in-app messages, SMS, and emails. OneSignal API keys can be used to access and send messages through these channels."
}
