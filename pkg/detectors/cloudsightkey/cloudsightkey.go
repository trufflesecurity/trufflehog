package cloudsightkey

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
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// CloudSight API keys can be:
	// 1. Random alphanumeric (20-50 chars)
	// 2. Prefixed with "alcht_" followed by digit
	keyPat = regexp.MustCompile(`\b([a-zA-Z0-9]{20,50}|alcht_[0-9][a-zA-Z0-9_-]{15,45})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"cloudsight", "cloud-sight", "cloud_sight"}
}

// FromData will find and optionally verify Cloudsightkey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		key := match[1]

		// Skip matches that are all letters (likely class names or identifiers)
		hasDigit := false
		for _, c := range key {
			if c >= '0' && c <= '9' {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			continue
		}

		// Find the position of this match in the data
		matchIdx := strings.Index(dataStr, key)
		if matchIdx == -1 {
			continue
		}

		// Check if CloudSight keywords appear within 200 chars before or after the match
		contextStart := matchIdx - 200
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := matchIdx + len(key) + 200
		if contextEnd > len(dataStr) {
			contextEnd = len(dataStr)
		}

		contextStr := strings.ToLower(dataStr[contextStart:contextEnd])
		if strings.Contains(contextStr, "cloudsight") ||
			strings.Contains(contextStr, "cloud-sight") ||
			strings.Contains(contextStr, "cloud_sight") {
			uniqueMatches[key] = struct{}{}
		}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_CloudsightKey,
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
	// CloudSight API endpoint - we'll use a simple request endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudsight.ai/v1/images", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("CloudSight %s", token))

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
		// Valid key
		return true, map[string]string{
			"rotation_guide": "https://cloudsight.ai/",
		}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Invalid key
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_CloudsightKey
}

func (s Scanner) Description() string {
	return "CloudSight API keys are used to access CloudSight's image recognition and computer vision API. These keys grant access to analyze and tag images using AI."
}
