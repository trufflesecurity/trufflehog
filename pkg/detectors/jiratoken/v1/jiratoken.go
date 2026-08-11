package jiratoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

func (Scanner) Version() int { return 1 }

// CloudEndpoint is used whenever the scanned data carries no Atlassian host of its own.
// reason: https://community.atlassian.com/forums/Jira-Product-Discovery-questions/Authorization-issues-with-GRAPHQL/qaq-p/2640943
// The graphql API answers on this host as long as the credentials are valid.
func (Scanner) CloudEndpoint() string { return "https://api.atlassian.com" }

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"atlassian", "confluence", "jira"}) + `\b([a-zA-Z-0-9]{24})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"atlassian", "confluence", "jira"}) + `\b((?:[a-zA-Z0-9-]{1,24}\.)+[a-zA-Z0-9-]{2,24}\.[a-zA-Z0-9-]{2,16})\b`)
	emailPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"atlassian", "confluence", "jira"}) + common.EmailPattern)

	invalidHosts = simple.NewCache[struct{}]()

	errNoHost = errors.New("no such host")

	// atlassianDomains are the only hosts that can answer the verification request.
	// domainPat matches any domain-shaped string near an atlassian/jira/confluence keyword, so without
	// this filter the detector would send the email and token to unrelated hosts found in the same chunk.
	atlassianDomains = []string{"atlassian.net", "atlassian.com", "jira.com"}
)

// IsAtlassianHost reports whether host is owned by Atlassian and can therefore be used for verification.
func IsAtlassianHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range atlassianDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// EndpointHost reduces an endpoint to its bare host. Found domains arrive without a scheme while cloud and
// user-configured endpoints carry one, and the analyzer expects SecretParts["domain"] to be a bare host.
func EndpointHost(endpoint string) string {
	endpoint = strings.TrimSuffix(strings.TrimSpace(endpoint), "/")
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		return u.Host
	}
	return endpoint
}

// AtlassianEndpoints filters found domains down to the Atlassian-owned ones, as scheme-qualified
// endpoints suitable for EndpointSetter. The returned slice is sorted so results are deterministic.
func AtlassianEndpoints(domains map[string]struct{}) []string {
	endpoints := make([]string, 0, len(domains))
	for domain := range domains {
		if !IsAtlassianHost(domain) {
			continue
		}
		endpoints = append(endpoints, "https://"+domain)
	}
	sort.Strings(endpoints)
	return endpoints
}

// verificationURL builds the graphql URL for endpoint, which may be a bare host such as
// "acme.atlassian.net" or a full base URL such as a user-configured "https://jira.example.com".
func verificationURL(endpoint string) string {
	endpoint = strings.TrimSuffix(strings.TrimSpace(endpoint), "/")
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	return endpoint + "/gateway/api/graphql"
}

// WithCloudFallback treats the cloud endpoint as a fallback rather than an additional target. When the
// data carried its own Atlassian host, that host is the one worth checking: it is what the analyzer needs
// in SecretParts["domain"], and EndpointSetter would otherwise place the cloud endpoint ahead of it.
//
// cloudEndpoint is matched by host, so a user who explicitly configures the cloud host as their verifier
// endpoint has it dropped too when the data carried a host of its own.
func WithCloudFallback(endpoints []string, cloudEndpoint string, haveFound bool) []string {
	if !haveFound || cloudEndpoint == "" {
		return endpoints
	}

	cloudHost := EndpointHost(cloudEndpoint)
	kept := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		if EndpointHost(endpoint) == cloudHost {
			continue
		}
		kept = append(kept, endpoint)
	}
	return kept
}

// DedupeByHost drops endpoints that resolve to a host already seen, so a domain found in the data that
// also happens to be the cloud endpoint doesn't produce two identical results.
func DedupeByHost(endpoints []string) []string {
	seen := make(map[string]struct{}, len(endpoints))
	deduped := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		host := EndpointHost(endpoint)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		deduped = append(deduped, endpoint)
	}
	return deduped
}

type JIRAGraphQLResponse struct {
	Data struct {
		Me struct {
			User struct {
				Name string `json:"name"`
			} `json:"user"`
		} `json:"me"`
	} `json:"data"`
}

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

	// Verify against any user-configured endpoints and the Atlassian hosts found in the data, falling back
	// to the cloud endpoint only when the data carried no Atlassian host of its own.
	found := AtlassianEndpoints(uniqueDomains)
	endpoints := DedupeByHost(WithCloudFallback(s.Endpoints(found...), s.CloudEndpoint(), len(found) > 0))

	for email := range uniqueEmails {
		for token := range uniqueTokens {
			for _, endpoint := range endpoints {
				domain := EndpointHost(endpoint)
				if invalidHosts.Exists(domain) {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detector_typepb.DetectorType_JiraToken,
					Raw:          []byte(token),
					RawV2:        fmt.Appendf(nil, "%s:%s:%s", email, token, domain),
					ExtraData: map[string]string{
						"rotation_guide": "https://howtorotate.com/docs/tutorials/atlassian/",
						"version":        fmt.Sprintf("%d", s.Version()),
					},
					SecretParts: map[string]string{
						"token":  token,
						"domain": domain,
						"email":  email,
					},
				}

				if verify {
					client := s.getClient()
					isVerified, verificationErr := VerifyJiraToken(ctx, client, email, endpoint, token)
					s1.Verified = isVerified
					if verificationErr != nil {
						if errors.Is(verificationErr, errNoHost) {
							invalidHosts.Set(domain, struct{}{})
						}

						s1.SetVerificationError(verificationErr, token)
					}

					// The credential is the same across endpoints, so once one of them verifies it there
					// is nothing to learn from the rest.
					if s1.Verified {
						results = append(results, s1)
						break
					}
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

// VerifyJiraToken checks the credentials against endpoint, which may be a bare host or a full base URL.
func VerifyJiraToken(ctx context.Context, client *http.Client, email, endpoint, token string) (bool, error) {
	// wrap the query in a JSON body
	body := map[string]string{
		"query": `query verify { me { user { name } } }`,
	}

	// encode the body as JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return false, err
	}

	// api docs: https://developer.atlassian.com/platform/atlassian-graphql-api/graphql/#authentication
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verificationURL(endpoint), bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.SetBasicAuth(email, token)

	resp, err := client.Do(req)
	if err != nil {
		// lookup foo.test.net: no such host
		if strings.Contains(err.Error(), "no such host") {
			return false, errNoHost
		}

		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// the API returns 200 if the token is valid
	switch {
	case resp.StatusCode == http.StatusOK:
		var jiraResp JIRAGraphQLResponse
		if err := json.NewDecoder(resp.Body).Decode(&jiraResp); err != nil {
			return false, nil // can't decode response in case of 200 OK = not valid JIRA domain
		}

		// A 200 on its own isn't enough - unrelated hosts can also return JSON and get flagged as verified.
		// Only trust it when the body actually carries the authenticated user's name.
		return jiraResp.Data.Me.User.Name != "", nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		// The credentials were rejected. Nothing to retry.
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		// Rate limiting and server errors are genuinely transient, so keep them indeterminate
		// and let the secret be retried.
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	default:
		// Anything else (202, 3xx, 404, ...) is not an Atlassian authentication response at all.
		// domainPat matches any domain-shaped string near a jira/atlassian/confluence keyword, so this
		// request may well have gone to an unrelated host that happily accepts POSTs. Retrying will
		// return the same status forever, so treat it as a terminal "not verified" instead of an error.
		return false, nil
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_JiraToken
}

func (s Scanner) Description() string {
	return "Jira is a proprietary issue tracking product developed by Atlassian that allows bug tracking and agile project management. Jira tokens can be used to authenticate and interact with Jira's API."
}
