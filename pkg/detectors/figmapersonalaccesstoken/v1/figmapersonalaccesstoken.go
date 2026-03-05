package figmapersonalaccesstoken

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
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)

func (Scanner) Version() int { return 1 }

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"figma"}) + `\b([0-9]{6}-[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"figma"}
}

func (s Scanner) Description() string {
	return "Figma is a web-based design tool. Personal Access Tokens can be used to access and modify design files and other resources."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FigmaPersonalAccessToken,
			Raw:          []byte(resMatch),
			ExtraData: map[string]string{
				"version": fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			isVerified, verificationErr := VerifyMatch(ctx, s.getClient(), resMatch)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, resMatch)
			if s1.Verified {
				s1.AnalysisInfo = map[string]string{"token": resMatch}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FigmaPersonalAccessToken
}

// VerifyMatch checks if the provided Figma token is valid by making a request to the Figma API.
func VerifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.figma.com/v1/me", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("X-Figma-Token", token)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return true, nil
	case res.StatusCode == 403:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
