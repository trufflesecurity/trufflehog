package handlers

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/avast/apkparser"
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
			archiveURL:     "https://raw.githubusercontent.com/trufflesecurity/trufflehog-test-assets/main/aws_leak.apk",
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
			defer func() { _ = resp.Body.Close() }()

			handler := newAPKHandler()

			newReader, err := newFileReader(context.Background(), resp.Body)
			if err != nil {
				t.Errorf("error creating reusable reader: %s", err)
			}
			defer func() { _ = newReader.Close() }()

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

	rdr, err := newFileReader(ctx, io.NopCloser(reader))
	assert.NoError(t, err)
	defer func() { _ = rdr.Close() }()

	_, err = createZipReader(rdr)
	// Since processAPK no longer creates the zip reader, this now calls createZipReader directly to test the same
	// error path.
	assert.Contains(t, err.Error(), "zip: not a valid zip file")
}

func TestOpenValidZipInvalidAPK(t *testing.T) {
	// Grabbed from archive_test.go
	validZipURL := "https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip"

	resp, err := http.Get(validZipURL)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	defer func() { _ = resp.Body.Close() }()

	newReader, err := newFileReader(context.Background(), resp.Body)
	if err != nil {
		t.Errorf("error creating reusable reader: %s", err)
	}
	assert.NoError(t, err)
	defer func() { _ = newReader.Close() }()

	zipReader, err := createZipReader(newReader)
	assert.NoError(t, err)

	_, err = parseResTable(zipReader)
	assert.Contains(t, err.Error(), "resources.arsc file not found")
}

type mockResourceEntry struct {
	data *resourceEntryData
	err  error
}

type mockResourceProvider struct {
	entries map[uint32]mockResourceEntry
}

func (m *mockResourceProvider) GetEntry(id uint32) (*resourceEntryData, error) {
	e, ok := m.entries[id]
	if !ok {
		return nil, nil
	}
	return e.data, e.err
}

func TestExtractStringsFromResTable_SkipsBadEntries(t *testing.T) {
	provider := &mockResourceProvider{
		entries: map[uint32]mockResourceEntry{
			0x7f040000: {data: &resourceEntryData{Key: "app_name", ResourceType: "string", Value: "MyApp"}},
			0x7f040001: {data: &resourceEntryData{Key: "bad_entry", ResourceType: "string"}, err: apkparser.ErrUnknownResourceDataType},
			0x7f040002: {data: &resourceEntryData{Key: "api_key", ResourceType: "string", Value: "secret123"}},
			0x7f040003: {data: &resourceEntryData{Key: "icon", ResourceType: "drawable"}},
		},
	}

	rdr := extractStringsFromResTable(provider)
	data, err := io.ReadAll(rdr)
	assert.NoError(t, err)

	output := string(data)
	assert.Contains(t, output, "app_name: MyApp")
	assert.Contains(t, output, "api_key: secret123")
	assert.NotContains(t, output, "bad_entry")
}
