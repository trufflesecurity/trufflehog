package handlers

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestAPKHandler(t *testing.T) {
	tests := map[string]struct {
		archiveURL      string
		expectedChunks  int
		expectedSecrets int
		matchString     string
		expectErr       bool
	}{
		"apk_with_3_leaked_keys": {
			"https://github.com/joeleonjr/leakyAPK/raw/refs/heads/main/aws_leak.apk",
			401,
			3,
			"AKIA2UC3BSXMLSCLTUUS",
			false,
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Get(testCase.archiveURL)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			defer resp.Body.Close()

			handler := newAPKHandler()

			newReader, err := newFileReader(resp.Body)
			if err != nil {
				t.Errorf("error creating reusable reader: %s", err)
			}
			defer newReader.Close()

			archiveChan, err := handler.HandleFile(logContext.Background(), newReader)
			if testCase.expectErr {
				assert.NoError(t, err)
				return
			}

			chunkCount := 0
			secretCount := 0
			re := regexp.MustCompile(testCase.matchString)
			matched := false
			for chunk := range archiveChan {
				chunkCount++
				if re.Match(chunk) {
					secretCount++
					matched = true
				}
			}

			assert.True(t, matched)
			assert.Equal(t, testCase.expectedChunks, chunkCount)
			assert.Equal(t, testCase.expectedSecrets, secretCount)
		})
	}
}

func TestOpenInvalidAPK(t *testing.T) {
	reader := strings.NewReader("invalid apk")

	ctx := logContext.AddLogger(context.Background())
	handler := apkHandler{}

	rdr, err := newFileReader(io.NopCloser(reader))
	assert.NoError(t, err)
	defer rdr.Close()

	archiveChan := make(chan []byte)

	err = handler.processAPK(ctx, rdr, archiveChan)
	assert.Contains(t, err.Error(), "zip: not a valid zip file")
}

func TestOpenValidZipInvalidAPK(t *testing.T) {
	// Grabbed from archive_test.go
	validZipURL := "https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip"

	resp, err := http.Get(validZipURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	handler := newAPKHandler()

	newReader, err := newFileReader(resp.Body)
	if err != nil {
		t.Errorf("error creating reusable reader: %s", err)
	}
	assert.NoError(t, err)
	defer newReader.Close()

	archiveChan := make(chan []byte)
	ctx := logContext.AddLogger(context.Background())

	err = handler.processAPK(ctx, newReader, archiveChan)
	assert.Contains(t, err.Error(), "resources.arsc file not found")
}
