package sonarqube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/ssrf"
)

// Scanner finds SonarQube Server tokens: user (squ_), global analysis (sqa_)
// and project analysis (sqp_). A token has no host in it, so it is verified
// against endpoints the user configured and hosts found in the scanned data
// (see findEndpoints).
type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	detectors.EndpointSetter
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

// There is no public SonarQube Server, so there is no cloud endpoint.
func (Scanner) CloudEndpoint() string { return "" }

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(`\b(sq[apu]_[0-9a-f]{40})\b`)

	// Host after a sonar config key, any port, for example
	// sonar.host.url=https://sonar.example.com or SONAR_HOST_URL: sonar.example.com:8080
	hostURLPat = regexp.MustCompile(`(?i)\bsonar[._](?:host[._]url|host|url)\b["'\s:=,>]*((?:https?://)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?)`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"squ_", "sqa_", "sqp_"}
}

// findEndpoints returns the hosts in the data named by a sonar config key,
// each one once.
func findEndpoints(data string) []string {
	var endpoints []string
	seen := make(map[string]struct{})
	for _, match := range hostURLPat.FindAllStringSubmatch(data, -1) {
		if _, ok := seen[match[1]]; !ok {
			seen[match[1]] = struct{}{}
			endpoints = append(endpoints, match[1])
		}
	}
	return endpoints
}

// FromData will find and optionally verify SonarQube secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(string(data), -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	configured := s.Endpoints()
	endpoints := s.Endpoints(findEndpoints(string(data))...)

	for match := range uniqueMatches {
		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_SonarQube,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		// nowhere to verify, tell the user how to fix that
		if len(endpoints) == 0 {
			result.ExtraData = map[string]string{
				"message": "No SonarQube Server URL was found or configured. To verify this token, set the server URL as a custom endpoint, e.g. --verifier SonarQube=https://sonar.example.com",
			}
		}

		if verify {
			// try each endpoint, stop at the first one that accepts the token
			var verifyErr error
			for _, endpoint := range endpoints {
				// Hosts found in scanned data are not trusted, so they get a client
				// that refuses local and private addresses.
				client := s.client
				if client == nil {
					client = s.VerificationClient(defaultClient)
					if !slices.Contains(configured, endpoint) {
						client = detectors.DetectorHttpClientWithNoLocalAddresses
					}
				}

				isVerified, extraData, err := verifyMatch(ctx, client, endpoint, match)
				// a found host like localhost is the developer's machine, not ours, skip it
				if errors.Is(err, ssrf.ErrEgressBlocked) {
					continue
				}
				if err != nil {
					verifyErr = err
					continue
				}
				if isVerified {
					result.Verified = true
					result.ExtraData = extraData
					verifyErr = nil
					break
				}
			}
			result.SetVerificationError(verifyErr, match)
		}

		results = append(results, result)
	}

	return
}

type currentUserResponse struct {
	IsLoggedIn bool   `json:"isLoggedIn"`
	Login      string `json:"login"`
}

// verifyMatch asks the server who the token belongs to.
// The token goes in the basic auth username with an empty password.
// A wrong token gets a 401. We check isLoggedIn too, because a server
// that allows anonymous access answers 200 for any request.
func verifyMatch(ctx context.Context, client *http.Client, endpoint, token string) (bool, map[string]string, error) {
	// users pass "host:9000" or "http://host:9000", default to https
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	url := strings.TrimRight(endpoint, "/") + "/api/users/current"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil, err
	}
	req.SetBasicAuth(token, "")
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		var user currentUserResponse
		if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
			return false, nil, fmt.Errorf("failed to decode response: %w", err)
		}
		if !user.IsLoggedIn {
			return false, nil, nil
		}
		return true, map[string]string{"endpoint": endpoint, "login": user.Login}, nil
	case http.StatusUnauthorized:
		// the token is definitely not valid on this server
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SonarQube
}

func (s Scanner) Description() string {
	return "SonarQube Server is a code quality and security analysis platform. Its user, global analysis and project analysis tokens authenticate people and CI pipelines to the SonarQube API."
}
