package grafanaserviceaccount

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(`\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})\b`)
	domainPat = regexp.MustCompile(`\b([a-zA-Z0-9-]+\.grafana\.net)\b`)
)

//const noCloudFound = "No Grafana Cloud Instance associated"

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
// Grafana uses "glsa_" as a prefix for its service accounts, see for example.
// https://github.com/grafana/pyroscope-dotnet/blob/0c17634653af09befa7bc07b2e1c420b5dc8578c/tracer/src/Datadog.Trace/Iast/Analyzers/HardcodedSecretsAnalyzer.cs#L175
func (s Scanner) Keywords() []string {
	return []string{"glsa_"}
}

// FromData will find and optionally verify Grafanaserviceaccount secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, keyMatch := range keyMatches {
		key := strings.TrimSpace(keyMatch[1])

		if len(domainMatches) == 0 {
			res := detectors.Result{
				DetectorType: detectorspb.DetectorType_GrafanaServiceAccount,
				Raw:          []byte(key),
				RawV2:        []byte(key),
			}
			res.SetVerificationError(fmt.Errorf("no grafana instance detected to verify against"), key)
			results = append(results, res)
		} else if len(domainMatches) >= 1 {
			for _, domainMatch := range domainMatches {
				domainRes := strings.TrimSpace(domainMatch[1])

				res := detectors.Result{
					DetectorType: detectorspb.DetectorType_GrafanaServiceAccount,
					Raw:          []byte(key),
				}

				res.RawV2 = fmt.Appendf(nil, "%s:%s", domainRes, key)
				if verify {
					s.verifyGrafanaCloudServiceAccount(ctx, &res, domainRes, key)
				}
				results = append(results, res)
			}
		}
	}

	return results, nil
}

func (s Scanner) verifyGrafanaCloudServiceAccount(ctx context.Context, res *detectors.Result, domain, key string) {
	client := s.client
	if client == nil {
		client = defaultClient
	}

	url := fmt.Sprintf("https://%s/api/access-control/user/permissions", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			res.Verified = true
		case resp.StatusCode == 401:
			// determinately not verified
		default:
			res.SetVerificationError(fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode), key)
		}
	} else {
		res.SetVerificationError(err, key)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_GrafanaServiceAccount
}

func (s Scanner) Description() string {
	return "Grafana service accounts are used to authenticate and interact with Grafana's API. These credentials can be used to access and modify Grafana resources and settings."
}
