package mailgun

import (
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

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	tokenPats = map[string]*regexp.Regexp{
		"Original MailGun Token": regexp.MustCompile(detectors.PrefixRegex([]string{"mailgun"}) + `\b([a-zA-Z0-9-]{72})\b`),
		"Key-MailGun Token":      regexp.MustCompile(`\b(key-[a-z0-9]{32})\b`),
		"Hex MailGun Token":      regexp.MustCompile(`\b([a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})\b`),
	}
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mailgun", "key-"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Mailgun secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, tokenPat := range tokenPats {
		for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
			uniqueMatches[match[1]] = struct{}{}
		}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(match),
			AnalysisInfo: map[string]string{"key": match},
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// https://documentation.mailgun.com/docs/mailgun/api-reference/openapi-final/tag/Domains/
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mailgun.net/v3/domains", nil)
	if err != nil {
		return false, nil, err
	}

	if len(token) == 72 {
		// This matches prior logic, but may not be correct.
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", token))
	} else {
		// https://documentation.mailgun.com/docs/mailgun/api-reference/authentication/
		req.SetBasicAuth("api", token)
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode == http.StatusOK {
		var domains domainResponse
		if err := json.NewDecoder(res.Body).Decode(&domains); err != nil {
			return false, nil, fmt.Errorf("error decoding response body: %w", err)
		}

		var extraData map[string]string
		if len(domains.Items) > 0 {
			sb := strings.Builder{}
			for i, item := range domains.Items {
				if i != 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(item.Name)
				sb.WriteString(" (")
				sb.WriteString(item.State)
				sb.WriteString(",")
				sb.WriteString(item.Type)
				if item.IsDisabled {
					sb.WriteString(",disabled")
				}
				sb.WriteString(")")
			}
			extraData = map[string]string{
				"Domains": sb.String(),
			}
		}

		return true, extraData, nil
	} else if res.StatusCode == http.StatusUnauthorized {
		return false, nil, nil
	} else {
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

type domainResponse struct {
	TotalCount int    `json:"total_count"`
	Items      []item `json:"items"`
}

type item struct {
	ID         string `json:"id"`
	IsDisabled bool   `json:"is_disabled"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Type       string `json:"type"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mailgun
}

func (s Scanner) Description() string {
	return "Mailgun is an email automation service. Mailgun tokens can be used to send, receive, and track emails."
}
