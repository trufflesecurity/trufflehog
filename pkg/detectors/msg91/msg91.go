package msg91

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	// MSG91 auth keys are 28-32 character alphanumeric strings.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"msg91"}) + `\b([A-Za-z0-9]{28,32})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}

	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"msg91"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_MSG91
}

func (s Scanner) Description() string {
	return "MSG91 is an SMS/OTP communication platform. Auth keys grant full account access, including the ability to send messages and drain the account balance."
}

// FromData will find and optionally verify MSG91 secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_MSG91,
			Raw:          []byte(token),
			SecretParts: map[string]string{
				"key": token,
			},
		}

		if verify {
			isVerified, verificationErr := verifyMSG91(ctx, s.getClient(), token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyMSG91(ctx context.Context, client *http.Client, token string) (bool, error) {
	// The balance endpoint authenticates the key and returns the account balance.
	endpoint := "https://control.msg91.com/api/balance.php?type=4&authkey=" + url.QueryEscape(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, err
	}

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
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, err
		}
		// An invalid key still returns HTTP 200 but with an error message in the
		// body (e.g. "Invalid authkey") instead of a balance figure.
		if strings.Contains(strings.ToLower(string(body)), "invalid") {
			return false, nil
		}
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// The token is determinately invalid.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
