package pypi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
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

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile("(pypi-AgEIcHlwaS5vcmcCJ[a-zA-Z0-9-_]{150,157})")
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"pypi-AgEIcHlwaS5vcmcCJ"}
}

// FromData will find and optionally verify Pypi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_PyPI,
			Raw:          []byte(match),
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
	// Create a buffer to hold the multipart form data
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Add the form fields like in the curl request
	_ = writer.WriteField(":action", "file_upload")
	_ = writer.WriteField("name", "dummy-package")
	_ = writer.WriteField("version", "0.0.1")
	_ = writer.WriteField("content", "dummy-content")

	// Close the writer to finalize the form
	writer.Close()

	// Create a new POST request to the PyPI legacy upload URL
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://upload.pypi.org/legacy/", &body)
	if err != nil {
		return false, nil, err
	}

	// Add the Authorization header with the PyPI API token
	req.Header.Add("Authorization", "token "+token)
	// Set the Content-Type to the multipart form boundary
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Execute the HTTP request
	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// Check for expected status codes for verification
	if res.StatusCode == http.StatusBadRequest {
		verified, err := common.ResponseContainsSubstring(res.Body, "Include at least one message digest.")
		if err != nil {
			return false, nil, err
		}
		if verified {
			return true, nil, nil
		}
	} else if res.StatusCode == http.StatusForbidden {
		// If we get a 403 status, the key is invalid
		return false, nil, nil
	}

	// For all other status codes, return an error
	return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PyPI
}

func (s Scanner) Description() string {
	return "PyPI is a repository of software for the Python programming language. The credential allows for managing Pypi packages."
}
