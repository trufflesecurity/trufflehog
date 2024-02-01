package abuseipdb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

const abuseipdbURL = "https://api.abuseipdb.com"

var (
	// Ensure the Scanner satisfies the interface at compile time.
	_ detectors.Detector = (*Scanner)(nil)

	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"abuseipdb"}) + `\b([a-z0-9]{80})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"abuseipdb"}
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify AbuseIPDB secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_AbuseIPDB,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.getClient()
			isVerified, verificationErr := verifyAbuseIPDB(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
		}

		// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyAbuseIPDB(ctx context.Context, client *http.Client, resMatch string) (bool, error) {
	// https://docs.abuseipdb.com/#check-endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, abuseipdbURL+"/api/v2/check?ipAddress=8.8.8.8", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Key", resMatch)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		validResponse := bytes.Contains(bodyBytes, []byte("ipAddress"))
		if validResponse {
			return true, nil
		} else {
			return false, nil
		}
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AbuseIPDB
}
