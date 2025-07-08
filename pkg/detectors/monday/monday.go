package monday

import (
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

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"monday"}) + `\b(eyJ[A-Za-z0-9-_]{15,100}\.eyJ[A-Za-z0-9-_]{100,300}\.[A-Za-z0-9-_]{25,100})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"monday"}
}

// FromData will find and optionally verify Monday secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Monday,
			Raw:          []byte(resMatch),
		}

		if verify {
			isVerified, verificationErr := verifyMondayPAT(ctx, client, resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)

			if s1.Verified {
				s1.AnalysisInfo = map[string]string{
					"key": resMatch,
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Monday
}

func (s Scanner) Description() string {
	return "Monday.com is a work operating system that powers teams to run projects and workflows with confidence. Monday API keys can be used to access and modify data and workflows on the platform."
}

func verifyMondayPAT(ctx context.Context, client *http.Client, token string) (bool, error) {
	payload := strings.NewReader(`{"query":"{boards(limit:1){id name}}"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.monday.com/v2", payload)
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", token)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
