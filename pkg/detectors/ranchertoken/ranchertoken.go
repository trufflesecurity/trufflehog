package ranchertoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	detectors.EndpointSetter
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cattle", "rancher"}) + `\b([a-z0-9]{54,64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"cattle_token", "rancher_token", "cattle_bootstrap_password", "rancher_api_token", "rancher_secret_key"}
}

// FromData will find and optionally verify RancherToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_RancherToken,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"token": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			
			endpoints := s.Endpoints()
			if len(endpoints) == 0 {
				s1.Verified = false
				s1.SetVerificationError(fmt.Errorf("requires endpoint configuration"), match)
				results = append(results, s1)
				continue
			}

			var anyVerified bool
			var lastErr error
			for _, endpoint := range endpoints {
				endpointURL := strings.TrimSuffix(endpoint, "/")
				isVerified, extraData, verificationErr := verifyMatch(ctx, client, endpointURL, match)
				if isVerified {
					s1.Verified = true
					s1.ExtraData = extraData
					anyVerified = true
					break
				}
				if verificationErr != nil {
					lastErr = verificationErr
				}
			}

			if !anyVerified {
				s1.Verified = false
				s1.SetVerificationError(lastErr, match)
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, endpoint, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v3", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

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
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, nil, err
		}
		if strings.Contains(string(bodyBytes), "apiVersion") {
			return true, nil, nil
		}
		return false, nil, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_RancherToken
}

func (s Scanner) Description() string {
	return "Rancher is a Kubernetes management platform. Rancher tokens can provide full cluster admin access."
}
