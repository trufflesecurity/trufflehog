package newreliclicensekey

import (
	"context"
	"encoding/json"
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
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// New Relic License Keys are 40 alphanumeric characters (case-insensitive)
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"newrelic", "new_relic", "new-relic", "nr_license", "nrlicensekey"}
}

// FromData will find and optionally verify NewRelicLicenseKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := match[1]

		// Check if this appears near New Relic related keywords
		matchIdx := strings.Index(dataStr, key)
		if matchIdx == -1 {
			continue
		}

		// Check context window (200 chars before/after)
		contextStart := matchIdx - 200
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := matchIdx + len(key) + 200
		if contextEnd > len(dataStr) {
			contextEnd = len(dataStr)
		}

		contextStr := strings.ToLower(dataStr[contextStart:contextEnd])
		if strings.Contains(contextStr, "newrelic") ||
			strings.Contains(contextStr, "new_relic") ||
			strings.Contains(contextStr, "new-relic") ||
			strings.Contains(contextStr, "license") ||
			strings.Contains(contextStr, "ingest") {
			uniqueMatches[key] = struct{}{}
		}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_NewRelicLicenseKey,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// Try US region first
	verified, extraData, err := verifyRegion(ctx, client, token, "https://log-api.newrelic.com/log/v1")
	if verified || err != nil {
		return verified, extraData, err
	}

	// Try EU region if US fails
	return verifyRegion(ctx, client, token, "https://log-api.eu.newrelic.com/log/v1")
}

func verifyRegion(ctx context.Context, client *http.Client, token string, endpoint string) (bool, map[string]string, error) {
	// Send a test log event to verify the license key
	payload := `[{"message":"trufflehog verification test","timestamp":` + fmt.Sprintf("%d", 1000000000000) + `}]`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(payload))
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", token)

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusCreated:
		// Valid key - parse response if available
		region := "US"
		if strings.Contains(endpoint, ".eu.") {
			region = "EU"
		}

		extraData := map[string]string{
			"region":         region,
			"rotation_guide": "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
		}

		// Try to parse response for additional info
		bodyBytes, err := io.ReadAll(res.Body)
		if err == nil && len(bodyBytes) > 0 {
			var response struct {
				UUID string `json:"uuid"`
			}
			if err := json.Unmarshal(bodyBytes, &response); err == nil {
				if response.UUID != "" {
					extraData["request_id"] = response.UUID
				}
			}
		}

		return true, extraData, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Invalid key
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_NewRelicLicenseKey
}

func (s Scanner) Description() string {
	return "New Relic License Keys are 40-character hexadecimal keys used for data ingestion into New Relic. These keys grant access to send APM data, logs, metrics, and events to your New Relic account."
}
