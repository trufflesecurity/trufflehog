package handlers

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestAPKHandler(t *testing.T) {
	tests := map[string]struct {
		archiveURL      string
		expectedChunks  int
		expectedSecrets int
		matchString     string
	}{
		"apk_with_3_leaked_keys": {
			archiveURL:     "https://github.com/joeleonjr/leakyAPK/raw/refs/heads/main/aws_leak.apk",
			expectedChunks: 942,
			// Note: the secret count is 4 instead of 3 b/c we're not actually running the secret detection engine,
			// we're just looking for a string match. There is one extra string match in the APK (but only 3 detected secrets).
			expectedSecrets: 4,
			matchString:     "AKIA2UC3BSXMLSCLTUUS",
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Get(testCase.archiveURL)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			defer resp.Body.Close()

			handler := newAPKHandler()

			newReader, err := newFileReader(context.Background(), resp.Body)
			if err != nil {
				t.Errorf("error creating reusable reader: %s", err)
			}
			defer newReader.Close()

			archiveChan := handler.HandleFile(context.Background(), newReader)

			chunkCount := 0
			secretCount := 0
			re := regexp.MustCompile(testCase.matchString)
			matched := false
			for chunk := range archiveChan {
				chunkCount++
				if re.Match(chunk.Data) {
					secretCount++
					matched = true
				}
			}

			assert.True(t, matched)
			// The APK handler's chunk count may increase over time as new keywords are added
			// as the default detector list grows. We use GreaterOrEqual to ensure the test remains
			// stable while allowing for this expected growth.
			assert.GreaterOrEqual(t, chunkCount, testCase.expectedChunks)
			assert.Equal(t, testCase.expectedSecrets, secretCount)
		})
	}
}

func TestOpenInvalidAPK(t *testing.T) {
	reader := strings.NewReader("invalid apk")

	ctx := context.AddLogger(context.Background())
	handler := apkHandler{}

	rdr, err := newFileReader(ctx, io.NopCloser(reader))
	assert.NoError(t, err)
	defer rdr.Close()

	archiveChan := make(chan DataOrErr)

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

	newReader, err := newFileReader(context.Background(), resp.Body)
	if err != nil {
		t.Errorf("error creating reusable reader: %s", err)
	}
	assert.NoError(t, err)
	defer newReader.Close()

	archiveChan := make(chan DataOrErr)
	ctx := context.AddLogger(context.Background())

	err = handler.processAPK(ctx, newReader, archiveChan)
	assert.Contains(t, err.Error(), "resources.arsc file not found")
}
