package microsoftteamswebhook

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

func (s Scanner) Version() int { return 2 }

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// urlPat matches the base Power Automate webhook URL plus its query string.
	// The path is matched strictly; the query string is matched loosely so that
	// parameter ordering changes in the future do not break detection.
	// Example: https://default<envId>.<region>.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/<workflowId>/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=<sig>
	urlPat = regexp.MustCompile(`https://[a-z0-9]+\.\d+\.environment\.api\.powerplatform\.com(?::\d+)?/powerautomate/automations/direct/workflows/[a-f0-9]{32}/triggers/manual/paths/invoke\?[^\s"'<>]+`)

	// sigPat extracts the sig parameter value from anywhere in the query string.
	sigPat = regexp.MustCompile(`[?&]sig=([A-Za-z0-9_\-]+)`)
)

func (s Scanner) Keywords() []string {
	return []string{"environment.api.powerplatform.com"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, urlMatch := range urlPat.FindAllString(dataStr, -1) {
		// sig is the signing key that authenticates the request; without it the URL is not a valid credential.
		if sigPat.MatchString(urlMatch) {
			uniqueMatches[strings.TrimSpace(urlMatch)] = struct{}{}
		}
	}

	for secret := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_MicrosoftTeamsWebhook,
			Raw:          []byte(secret),
			SecretParts:  map[string]string{"key": secret},
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, verificationErr := verifyWebhook(ctx, client, secret)
			r.Verified = isVerified
			r.SetVerificationError(verificationErr, secret)
		}

		results = append(results, r)
	}
	return results, nil
}

// verifyWebhook sends a POST request to the webhook URL to verify it is active.
// A 202 response indicates the credential is valid; 400 means the webhook is disabled
// or deleted; 401 means unauthorized.
// The payload sends an empty text and intentionally omits the "type" field so the Power Automate flow accepts
// the request (returning 202) but does not deliver any message to the Teams channel.
func verifyWebhook(ctx context.Context, client *http.Client, webhookURL string) (bool, error) {
	payload := strings.NewReader(`{"text":""}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, payload)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusAccepted:
		return true, nil
	case http.StatusUnauthorized, http.StatusBadRequest:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// IsFalsePositive implements detectors.CustomFalsePositiveChecker.
// The raw value is a full webhook URL, not a short token, so wordlist-based
// false positive detection is not applicable.
func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_MicrosoftTeamsWebhook
}

func (s Scanner) Description() string {
	return "Microsoft Teams Webhooks (Power Automate) allow external services to communicate with Teams channels by sending messages to a unique Power Automate workflow URL."
}
