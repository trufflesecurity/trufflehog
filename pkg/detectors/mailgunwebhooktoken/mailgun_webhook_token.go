package mailgunwebhooktoken

import (
	"context"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	// Mailgun webhook signing tokens are commonly represented as 32 hex characters.
	// Require "mailgun" in nearby context to reduce noise from generic webhook examples.
	tokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mailgun"}) + `\b([a-fA-F0-9]{32})(?:['"|\n\r\s\x60;]|$)`)
)

func (s Scanner) Keywords() []string {
	return []string{"mailgun", "webhook", "signing"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_MailgunWebhookToken
}

func (s Scanner) Description() string {
	return "Mailgun webhook tokens are used to verify webhook payload signatures."
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) < 2 {
			continue
		}
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	results := make([]detectors.Result, 0, len(uniqueMatches))
	for token := range uniqueMatches {
		results = append(results, detectors.Result{
			DetectorType: detector_typepb.DetectorType_MailgunWebhookToken,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://help.mailgun.com/hc/en-us/articles/360018328934-How-can-I-verify-webhooks",
			},
			SecretParts: map[string]string{"token": token},
		})
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}
