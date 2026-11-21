package daytona

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client   *http.Client
	endpoint string
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Daytona API keys have the form dtn_ followed by 64 lowercase hex
	// characters (generateRandomString(32) is crypto.randomBytes(32)
	// rendered as hex, prefixed with dtn_).
	keyPat = regexp.MustCompile(`\b(dtn_[0-9a-f]{64})\b`)

	// https://www.daytona.io/docs/api-keys/
	// GET /api/sandbox lists the sandboxes visible to the key.
	defaultEndpoint = "https://app.daytona.io/api/sandbox"
)

func (s Scanner) Keywords() []string {
	return []string{"dtn_"}
}

// FromData will find and optionally verify Daytona secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Daytona,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"rotation_guide": "https://www.daytona.io/docs/api-keys/",
			},
			SecretParts: map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, s.verifyEndpoint(), match)
			s1.Verified = isVerified
			for k, v := range extraData {
				s1.ExtraData[k] = v
			}
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func (s Scanner) verifyEndpoint() string {
	if s.endpoint != "" {
		return s.endpoint
	}
	return defaultEndpoint
}

func verifyMatch(ctx context.Context, client *http.Client, endpoint, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

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
		// The key is valid and can list sandboxes.
		return true, nil, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Daytona
}

func (s Scanner) Description() string {
	return "Daytona is a platform for creating and managing sandboxes for running code. Daytona API keys can be used to access sandboxes in an organization."
}
