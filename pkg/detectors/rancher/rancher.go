package rancher

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	tokenPattern = regexp.MustCompile(
		`(?i)(?:CATTLE_TOKEN|RANCHER_TOKEN|CATTLE_BOOTSTRAP_PASSWORD|RANCHER_API_TOKEN)[^\w]{1,4}([a-z0-9]{54,64})`,
	)
	serverPattern = regexp.MustCompile(
		`(?i)(?:CATTLE_SERVER|RANCHER_URL|rancher\.[a-z0-9-]+\.[a-z]{2,})`,
	)
)

func (s Scanner) Keywords() []string {
	return []string{"cattle_token", "rancher_token", "rancher_api_token", "cattle_bootstrap_password"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	if !serverPattern.MatchString(dataStr) {
		return
	}

	matches := tokenPattern.FindAllStringSubmatch(dataStr, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		token := match[1]

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Rancher,
			Raw:          []byte(token),
		}

		if verify {
			client := common.SaneHttpClient()
			req, err := http.NewRequestWithContext(ctx, "GET", "https://rancher.example.com/v3", nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+token)
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close()
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
