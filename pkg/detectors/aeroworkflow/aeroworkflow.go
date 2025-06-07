package aeroworkflow

import (
	"context"
	"fmt"
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

const aeroworkflowURL = "https://api.aeroworkflow.com"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"aeroworkflow"}) + `\b([a-zA-Z0-9^!?#:*;]{20})`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"aeroworkflow"}) + `\b([0-9]{1,})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"aeroworkflow"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify Aeroworkflow secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idmatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, idmatch := range idmatches {
			resIdMatch := strings.TrimSpace(idmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Aeroworkflow,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resIdMatch),
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyAeroworkflow(ctx, client, resMatch, resIdMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}

	}

	return results, nil
}

func verifyAeroworkflow(ctx context.Context, client *http.Client, resMatch, resIdMatch string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, aeroworkflowURL+"/api/"+resIdMatch+"/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("apikey", resMatch)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	// https://api.aeroworkflow.com/swagger/index.html
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// 401 for invalid API key
		// 403 for invalid Account ID
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Aeroworkflow
}

func (s Scanner) Description() string {
	return "Aeroworkflow is a service for managing workflows. Aeroworkflow API keys and Account IDs can be used to access and manage workflows."
}
