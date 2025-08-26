package captaindata

import (
	"context"
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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 2 }

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"captaindata"}) + `\b([0-9a-f]{64})\b`)
	projIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"captaindata"}) + `\b([0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"captaindata"}
}

// FromData will find and optionally verify CaptainData secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	uniqueProjIdMatches := make(map[string]struct{})
	for _, match := range projIdPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueProjIdMatches[match[1]] = struct{}{}
	}

	for projId := range uniqueProjIdMatches {
		for apiKey := range uniqueMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CaptainData,
				Raw:          []byte(apiKey),
				RawV2:        []byte(projId + apiKey),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, client, projId, apiKey)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, apiKey)
			}

			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, projId, apiKey string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.captaindata.co/v3/workspace", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "x-api-key "+apiKey)
	req.Header.Set("x-project-id", projId)

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
		return true, nil, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CaptainData
}

func (s Scanner) Description() string {
	return "CaptainData is a service for automating data extraction and processing. The API keys can be used to access and control these automation processes."
}
