package jiratoken

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

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 1 }

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"atlassian", "confluence", "jira"}) + `\b([a-zA-Z-0-9]{24})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"atlassian", "confluence", "jira"}) + `\b((?:[a-zA-Z0-9-]{1,24}\.)+[a-zA-Z0-9-]{2,24}\.[a-zA-Z0-9-]{2,16})\b`)
	emailPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"atlassian", "confluence", "jira"}) + common.EmailPattern)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"atlassian", "confluence", "jira"}
}

// FromData will find and optionally verify JiraToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueTokens, uniqueDomains, uniqueEmails = make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})

	for _, token := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueTokens[token[1]] = struct{}{}
	}

	for _, domain := range domainPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueDomains[domain[1]] = struct{}{}
	}

	for _, email := range emailPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEmails[strings.ToLower(email[1])] = struct{}{}
	}

	if len(uniqueDomains) == 0 {
		// reason: https://community.atlassian.com/forums/Jira-Product-Discovery-questions/Authorization-issues-with-GRAPHQL/qaq-p/2640943
		// In case we don't find any domain matches we can use this as the graphql API works with this domain if our authentication is valid
		uniqueDomains["api.atlassian.com"] = struct{}{}
	}

	for email := range uniqueEmails {
		for token := range uniqueTokens {
			for domain := range uniqueDomains {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_JiraToken,
					Raw:          []byte(token),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", email, token, domain)),
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/atlassian/",
						"version":        fmt.Sprintf("%d", s.Version()),
					},
				}

				if verify {
					client := s.getClient()
					isVerified, verificationErr := VerifyJiraToken(ctx, client, email, domain, token)
					s1.Verified = isVerified
					s1.SetVerificationError(verificationErr, token)
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func VerifyJiraToken(ctx context.Context, client *http.Client, email, domain, token string) (bool, error) {
	// wrap the query in a JSON body
	body := map[string]string{
		"query": `verify { me { user {name}}}`,
	}

	// encode the body as JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, err
	}

	// api docs: https://developer.atlassian.com/platform/atlassian-graphql-api/graphql/#authentication
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+domain+"/gateway/api/graphql", bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(email, token)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// the API returns 200 if the token is valid
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JiraToken
}

func (s Scanner) Description() string {
	return "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate and interact with Jira's API."
}
