package satismeterwritekey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	writeKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([a-z0-9A-Z]{32})\b`)
	tokenPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([A-Za-z0-9]{32})\b`)
	projectPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"satismeter"}) + `\b([a-zA-Z0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"satismeter"}
}

// FromData will find and optionally verify SatismeterWritekey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueProjectMatches, uniqueWriteKeyMatches, uniqueTokenMatches := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, match := range projectPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueProjectMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range writeKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueWriteKeyMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokenMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for projectID := range uniqueProjectMatches {
		for token := range uniqueTokenMatches {
			for writeKey := range uniqueWriteKeyMatches {
				// writekey and token has same pattern, so skip the process when both values are same
				if token == writeKey {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_SatismeterWritekey,
					Raw:          []byte(projectID),
					RawV2:        []byte(projectID + writeKey),
				}

				if verify {
					isVerified, verificationErr := verifySatisMeterWriteKey(ctx, client, projectID, writeKey, token)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, writeKey)
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SatismeterWritekey
}

func (s Scanner) Description() string {
	return "Satismeter is a customer feedback platform. Satismeter Writekeys can be used to send event data to Satismeter's API."
}

// API Docs with payload details: https://support.satismeter.com/hc/en-us/articles/6980481518227-Track-event-API
func verifySatisMeterWriteKey(ctx context.Context, client *http.Client, projectID, writeKey, token string) (bool, error) {
	payload := createPayload(writeKey, projectID)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://app.satismeter.com/api/users?type=track", bytes.NewBuffer(payload))
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// createPayload creates a payload for POST api with writekey and projectID
func createPayload(writeKey, projectID string) []byte {
	// create the payload as a map
	payload := map[string]interface{}{
		"type":     "track",
		"userId":   "007",
		"event":    "This is the event name",
		"writeKey": writeKey,
		"project":  projectID,
	}

	// convert payload to JSON
	payloadBytes, _ := json.Marshal(payload)

	return payloadBytes
}
