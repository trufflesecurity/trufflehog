package atlassian

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

func (s Scanner) Version() int { return 2 }

type OrgRes struct {
	Data []struct {
		Attributes struct {
			Name string `json:"name"`
		} `json:"attributes"`
	} `json:"data"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.

	// Example: ATCTT3xFfGN0GsZNgOGrQSHSnxiJVi00oHlRicyM0yMNuKCBfw6qOHVcCy4Hm89GnclGb_W-1qAkxqCn5XbuyoX54bNhpK5yFKGFR7ocV6FByvL_P9Sb3tFnbUg3T3I3S_RGCBLMSN7Nsa4GJv8JEJ6bzvDmX-oJ8AnrazMU-zZ5hb-u3t2ERew=366BFE3A
	keyPat = regexp.MustCompile(`\b(ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`)
	// Example: 123e4567-e89b-12d3-a456-426614174000
	organizationIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"org", "id"}) + `\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ATCTT3xFfG"}
}

// Description returns a description for the result being detected
func (s Scanner) Description() string {
	return "Atlassian is a software company that provides tools for project management, software development, and collaboration. Atlassian tokens can be used to access and manage these tools and services."
}

// FromData will find and optionally verify Atlassian secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	uniqueOrgIdMatches := make(map[string]struct{})
	for _, match := range organizationIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueOrgIdMatches[match[1]] = struct{}{}
	}
	if len(uniqueOrgIdMatches) == 0 {
		// we only need an org ID to pass into AnalysisInfo
		// if we don't find one, we can still verify the key
		// we can add a dummy entry here just to make sure a result is returned
		uniqueOrgIdMatches[""] = struct{}{}
	}

	for match := range uniqueMatches {
		for orgId := range uniqueOrgIdMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Atlassian,
				Raw:          []byte(match),
				ExtraData: map[string]string{
					"rotation_guide": "https://howtorotate.com/docs/tutorials/atlassian/",
					"version":        fmt.Sprintf("%d", s.Version()),
				},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, orgResponse, verificationErr := verifyMatch(ctx, client, match)
				s1.Verified = isVerified
				if orgResponse != nil && len(orgResponse.Data) > 0 {
					s1.ExtraData["Organization"] = orgResponse.Data[0].Attributes.Name
				}
				s1.SetVerificationError(verificationErr, match)
				if s1.Verified {
					s1.AnalysisInfo = map[string]string{
						"key": match,
					}
					if orgId != "" {
						s1.AnalysisInfo["organization_id"] = orgId
					}
				}
			}

			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, *OrgRes, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.atlassian.com/admin/v1/orgs", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
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
		// If the endpoint returns useful information, we can return it as a map.
		var orgResponse OrgRes
		if err = json.NewDecoder(res.Body).Decode(&orgResponse); err != nil {
			return false, nil, err
		}
		return true, &orgResponse, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Atlassian
}
