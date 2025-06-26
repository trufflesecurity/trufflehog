package datadogtoken

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

func (Scanner) CloudEndpoint() string { return "https://api.datadoghq.com" }

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	appPat = regexp.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{40})\b`)
	apiPat = regexp.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{32})\b`)
)

type userServiceResponse struct {
	Data     []*user    `json:"data"`
	Included []*options `json:"included"`
}

type user struct {
	Attributes userAttributes `json:"attributes"`
}

type userAttributes struct {
	Email            string `json:"email"`
	IsServiceAccount bool   `json:"service_account"`
	Verified         bool   `json:"verified"`
	Disabled         bool   `json:"disabled"`
}

type options struct {
	Type       string          `json:"type"`
	Attributes optionAttribute `json:"attributes"`
}

type optionAttribute struct {
	Url      string `json:"url"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
}

func setUserEmails(data []*user, s1 *detectors.Result) {
	var emails []string
	for _, user := range data {
		// filter out non verified emails, disabled emails, service accounts
		if user.Attributes.Verified && !user.Attributes.Disabled && !user.Attributes.IsServiceAccount {
			emails = append(emails, user.Attributes.Email)
		}
	}

	if len(emails) == 0 && len(data) > 0 {
		emails = append(emails, data[0].Attributes.Email)
	}

	s1.ExtraData["user_emails"] = strings.Join(emails, ", ")
}

func setOrganizationInfo(opt []*options, s1 *detectors.Result) {
	var orgs *options
	for _, option := range opt {
		if option.Type == "orgs" && !option.Attributes.Disabled {
			orgs = option
			break
		}
	}

	if orgs != nil {
		s1.ExtraData["org_name"] = orgs.Attributes.Name
		s1.ExtraData["org_url"] = orgs.Attributes.Url
	}

}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"datadog"}
}

// FromData will find and optionally verify DatadogToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	appMatches := appPat.FindAllStringSubmatch(dataStr, -1)
	apiMatches := apiPat.FindAllStringSubmatch(dataStr, -1)

	for _, apiMatch := range apiMatches {
		resApiMatch := strings.TrimSpace(apiMatch[1])
		appIncluded := false
		for _, appMatch := range appMatches {
			resAppMatch := strings.TrimSpace(appMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatadogToken,
				Raw:          []byte(resAppMatch),
				RawV2:        []byte(resAppMatch + resApiMatch),
				ExtraData: map[string]string{
					"Type": "Application+APIKey",
				},
			}

			if verify {
				for _, baseURL := range s.Endpoints() {
					req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v2/users", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("DD-API-KEY", resApiMatch)
					req.Header.Add("DD-APPLICATION-KEY", resAppMatch)
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
							s1.AnalysisInfo = map[string]string{"apiKey": resApiMatch, "appKey": resAppMatch}
							var serviceResponse userServiceResponse
							if err := json.NewDecoder(res.Body).Decode(&serviceResponse); err == nil {
								// setup emails
								if len(serviceResponse.Data) > 0 {
									setUserEmails(serviceResponse.Data, &s1)
								}
								// setup organizations
								if len(serviceResponse.Included) > 0 {
									setOrganizationInfo(serviceResponse.Included, &s1)
								}
							}
						}
					}
				}
			}
			appIncluded = true
			results = append(results, s1)
		}

		if !appIncluded {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatadogToken,
				Raw:          []byte(resApiMatch),
				RawV2:        []byte(resApiMatch),
				ExtraData: map[string]string{
					"Type": "APIKeyOnly",
				},
			}

			if verify {
				for _, baseURL := range s.Endpoints() {
					req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v1/validate", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("DD-API-KEY", resApiMatch)
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
							s1.AnalysisInfo = map[string]string{"apiKey": resApiMatch}
						}
					}
				}
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DatadogToken
}

func (s Scanner) Description() string {
	return "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog."
}
