package rancher

import (
	"context"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	tokenPattern = regexp.MustCompile(
		`(?i)(?:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN)[\w]*\s*[=:]\s*["']?([a-z0-9]{54,64})["']?`,
	)
	serverPattern = regexp.MustCompile(
		`(?i)(?:CATTLE_SERVER|RANCHER_URL)\s*[=:]\s*["']?(https?://[a-zA-Z0-9._\-]+(:\d+)?)["']?`,
	)
)

func (s Scanner) Keywords() []string {
	return []string{"cattle_token", "rancher_token", "rancher_api_token", "cattle_bootstrap_password"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	serverMatches := serverPattern.FindStringSubmatch(dataStr)
	if len(serverMatches) < 2 {
		return
	}
	serverURL := strings.TrimRight(serverMatches[1], "/")

	matches := tokenPattern.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		token := match[1]

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Rancher,
			Raw:          []byte(token),
			RawV2:        []byte(serverURL + ":" + token),
		}

		if verify {
			client := common.SaneHttpClient()
			req, err := http.NewRequestWithContext(ctx, "GET", serverURL+"/v3", nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+token)
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode == http.StatusOK {
					result.Verified = true
				}
			}
		}

		results = append(results, result)
	}
	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Rancher
}

func (s Scanner) Description() string {
	return "Rancher is a Kubernetes management platform. Rancher API tokens can be used to gain full cluster admin access."
}