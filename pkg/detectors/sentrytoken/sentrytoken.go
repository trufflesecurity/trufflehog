package sentrytoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sentry"}) + `\b([a-f0-9]{64})\b`)

	errUnauthorized = fmt.Errorf("token unauthorized")
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("sentry")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := bytes.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_SentryToken,
			Raw:          resMatch,
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, verificationErr := verifyToken(ctx, client, string(resMatch))

			switch {
			case errors.Is(verificationErr, errUnauthorized):
				s1.Verified = false
			case isVerified:
				s1.Verified = true
			default:
				s1.VerificationError = verificationErr
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}
		results = append(results, s1)
	}

	return results, nil
}

type Response []Project

type Project struct {
	Organization Organization `json:"organization"`
}

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func verifyToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://sentry.io/api/0/projects/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	var isVerified bool
	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		isVerified = true
	case http.StatusUnauthorized:
		return false, errUnauthorized
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	bytes, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		return false, readErr
	}

	var resp Response
	if err = json.Unmarshal(bytes, &resp); err != nil {
		return false, err
	}

	return isVerified, err
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SentryToken
}
