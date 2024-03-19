package slackwebhook

import (
	"bytes"
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
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
	keyPat = regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"hooks.slack.com"}
}

// FromData will find and optionally verify SlackWebhook secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SlackWebhook,
			Raw:          []byte(resMatch),
		}
		s1.ExtraData = map[string]string{
			"rotation_guide": "https://howtorotate.com/docs/tutorials/slack-webhook/",
		}

		if verify {

			client := s.client
			if client == nil {
				client = defaultClient
			}

			// We don't want to actually send anything to webhooks we find. To verify them without spamming them, we
			// send an intentionally malformed message and look for a particular expected error message.
			payload := strings.NewReader(`intentionally malformed JSON from TruffleHog scan`)
			req, err := http.NewRequestWithContext(ctx, "POST", resMatch, payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}

				defer res.Body.Close()

				switch {
				case res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices:
					// Hopefully this never happens - it means we actually sent something to a channel somewhere. But
					// we at least know the secret is verified.
					s1.Verified = true
				case res.StatusCode == http.StatusBadRequest && bytes.Equal(bodyBytes, []byte("invalid_payload")):
					s1.Verified = true
				case res.StatusCode == http.StatusNotFound:
					// Not a real webhook or the owning app's OAuth token has been revoked or the app has been deleted
					// You might want to handle this case or log it.
				default:
					err = fmt.Errorf("unexpected HTTP response status %d: %s", res.StatusCode, bodyBytes)
					s1.SetVerificationError(err, resMatch)
				}
			} else {
				s1.SetVerificationError(err, resMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SlackWebhook
}
