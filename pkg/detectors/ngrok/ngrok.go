package ngrok

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

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Ngrok
}

func (s Scanner) Description() string {
	return "Ngrok is a service that provides secure introspectable tunnels to localhost. Ngrok keys can be used to manage and control these tunnels."
}

func (s Scanner) Keywords() []string {
	return []string{"ngrok"}
}

const (
	ngrokVerificationURL      = "https://api.ngrok.com/agent_ingresses"
	tunnelCredentialErrorCode = "ERR_NGROK_206"
)

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ngrok"}) + `\b(2[a-zA-Z0-9]{26}_\d[a-zA-Z0-9]{20})\b`)
)

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		m := match[1]
		if detectors.StringShannonEntropy(m) < 3 {
			continue
		}
		uniqueMatches[m] = struct{}{}
	}

	for token := range uniqueMatches {
		r := detectors.Result{
			DetectorType: detectorspb.DetectorType_Ngrok,
			Raw:          []byte(token),
		}

		if verify {
			if s.client == nil {
				s.client = common.SaneHttpClient()
			}
			isVerified, vErr := verifyMatch(ctx, s.client, token)
			r.Verified = isVerified
			r.SetVerificationError(vErr, token)
			if isVerified {
				r.AnalysisInfo = map[string]string{"key": token}
			}
		}

		results = append(results, r)
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ngrokVerificationURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("ngrok-version", "2")
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusBadRequest:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		// Check if the error code is "ERR_NGROK_206" which indicates that
		// the credential is a valid tunnel Authtoken rather than an API key.
		if strings.Contains(string(bodyBytes), tunnelCredentialErrorCode) {
			return true, nil
		}
	}
	return false, fmt.Errorf("ngrok: unexpected status code: %d", res.StatusCode)
}
