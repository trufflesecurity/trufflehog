package mesibo

import (
	"bytes"
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

type apiResponse struct {
	Code int `json:"code"`
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mesibo"}) + `\b([0-9A-Za-z]{64})\b`)
)

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mesibo"}
}

// FromData will find and optionally verify Mesibo secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Mesibo,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			s1.Verified, err = s.verify(ctx, resMatch)
			if err != nil {
				s1.SetVerificationError(err, resMatch)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

// verify checks the validity of a Mesibo app token against the backend API.
// https://docs.mesibo.com/api/backend-api/
func (s Scanner) verify(ctx context.Context, token string) (bool, error) {

	// We use the `useradd` operation as a probe: a valid token will yield
	// code 400 (bad request due to missing required user parameters, but
	// authentication succeeded), whereas an invalid or unauthorized
	// token will yield a different code such as 401.
	payload, err := json.Marshal(map[string]string{"op": "useradd", "token": token})
	if err != nil {
		return false, fmt.Errorf("failed to marshal request payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.mesibo.com/backend", bytes.NewBuffer(payload))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.getClient().Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	// The backend API always returns HTTP 200, with the actual result encoded in the
	// JSON response body.
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}
	var result apiResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return false, fmt.Errorf("failed to unmarshal response body: %w", err)
	}
	// The `code` field contains an RFC 9110 compliant HTTP status
	// code indicating the outcome of the operation.
	switch result.Code {
	case http.StatusBadRequest:
		// code 400 means valid token (bad request due to missing params, but auth passed)
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected code field: %d", result.Code)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Mesibo
}

func (s Scanner) Description() string {
	return "Mesibo is a real-time communication platform that allows developers to add messaging, voice, and video calls to their apps. Mesibo tokens can be used to access and interact with the Mesibo API."
}
