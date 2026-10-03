package solarwindsobservability

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var regions = []string{"na-01", "na-02", "eu-01", "ap-01"}

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"solarwinds"}) + `\b([0-9a-zA-Z_-]{71})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"solarwinds"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_SolarWindsObservability,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, region, verificationErr := verifySolarWindsObservability(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
			if region != "" {
				s1.SecretParts["region"] = region
				s1.ExtraData = map[string]string{"region": region}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifySolarWindsObservability tries the token against each regional endpoint and returns the
// region it verified against, if any.
func verifySolarWindsObservability(ctx context.Context, client *http.Client, token string) (bool, string, error) {
	var lastErr error
	for _, region := range regions {
		url := fmt.Sprintf("https://api.%s.cloud.solarwinds.com/v1/metrics", region)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

		res, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		verified, regionErr := func() (bool, error) {
			defer func() { _ = res.Body.Close() }()
			switch res.StatusCode {
			case http.StatusOK:
				return true, nil
			case http.StatusUnauthorized:
				return false, nil
			default:
				return false, fmt.Errorf("unexpected HTTP response status %d from region %s", res.StatusCode, region)
			}
		}()

		if verified {
			return true, region, nil
		}
		if regionErr != nil {
			lastErr = regionErr
		}
	}

	return false, "", lastErr
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SolarWindsObservability
}

func (s Scanner) Description() string {
	return "SolarWinds Observability is a cloud-based SaaS observability platform (successor to AppOptics). Its API tokens can be used to access and manage monitoring data and configurations."
}
