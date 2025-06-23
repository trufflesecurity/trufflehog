package dropbox

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	keyPat        = regexp.MustCompile(detectors.PrefixRegex([]string{"dropbox"}) + `\b(sl\.(u\.)?[A-Za-z0-9\-\_]{130,})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"dropbox", "sl."}
}

// FromData will find and optionally verify Dropbox secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueKeys = make(map[string]struct{})

	for _, matches := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[matches[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Dropbox,
			Raw:          []byte(key),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyDropboxToken(ctx, client, key)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr)
			if s1.Verified {
				s1.AnalysisInfo = map[string]string{"token": key}
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyDropboxToken(ctx context.Context, client *http.Client, key string) (bool, error) {
	// Reference: https://www.dropbox.com/developers/documentation/http/documentation
	url := "https://api.dropboxapi.com/2/users/get_current_account"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))
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
	case http.StatusUnauthorized, http.StatusBadRequest:
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read response body: %w", err)
		}
		body := string(bodyBytes)

		if strings.Contains(body, "missing_scope") ||
			strings.Contains(body, "does not have the required scope") {
			return true, nil // The token is valid but lacks the required scope
		}
		if strings.Contains(body, "invalid_access_token") ||
			strings.Contains(body, "expired_access_token") {
			return false, nil // The token is invalid or expired
		}
		return false, fmt.Errorf("unexpected status code: %d, body: %s", res.StatusCode, body)
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Dropbox
}

func (s Scanner) Description() string {
	return "Dropbox is a file hosting service that offers cloud storage, file synchronization, personal cloud, and client software. Dropbox API keys can be used to access and manage files and folders in a Dropbox account."
}
