package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestArchiveHandler(t *testing.T) {
	tests := map[string]struct {
		archiveURL     string
		expectedChunks int
		matchString    string
	}{
		"gzip-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/one-zip.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"gzip-nested": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/double-zip.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"gzip-too-deep": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/six-zip.gz",
			0,
			"",
		},
		"tar-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/one.tar",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"tar-nested": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/two.tar",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"tar-too-deep": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/six.tar",
			0,
			"",
		},
		"targz-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/tar-archive.tar.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"gzip-large": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/FifteenMB.gz",
			1543,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"zip-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
	}

	for name, testCase := range tests {
		resp, err := http.Get(testCase.archiveURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Error(err)
		}
		defer resp.Body.Close()

		archive := Archive{}
		archive.New()

		newReader, err := diskbufferreader.New(resp.Body)
		if err != nil {
			t.Errorf("error creating reusable reader: %s", err)
		}
		archiveChan := archive.FromFile(context.TODO(), newReader)

		count := 0
		re := regexp.MustCompile(testCase.matchString)
		matched := false
		for chunk := range archiveChan {
			count++
			if re.Match(chunk) {
				matched = true
			}
		}
		if !matched && len(testCase.matchString) > 0 {
			t.Errorf("%s: Expected string not found in archive.", name)
		}
		if count != testCase.expectedChunks {
			t.Errorf("%s: Unexpected number of chunks. Got %d, expected: %d", name, count, testCase.expectedChunks)
		}
	}
}

func TestHandleFile(t *testing.T) {
	ch := make(chan *sources.Chunk, 2)

	// Context cancels the operation.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.False(t, HandleFile(canceledCtx, strings.NewReader("file"), &sources.Chunk{}, ch))

	// Only one chunk is sent on the channel.
	// TODO: Embed a zip without making an HTTP request.
	resp, err := http.Get("https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip")
	assert.NoError(t, err)
	defer resp.Body.Close()
	archive := Archive{}
	archive.New()
	reader, err := diskbufferreader.New(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(ch))
	assert.True(t, HandleFile(context.Background(), reader, &sources.Chunk{}, ch))
	assert.Equal(t, 1, len(ch))
}
