package handlers

import (
	"bytes"
	_ "embed"
	"regexp"
	"strings"
	"testing"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

var (
	//go:embed testdata/aws.png
	png []byte
	//go:embed testdata/aws.pdf
	pdf []byte
	//go:embed testdata/aws.rtf
	rtf []byte
	//go:embed testdata/aws.odt
	odt []byte
	//go:embed testdata/aws.docx
	docx []byte
)

func TestTikaHandler(t *testing.T) {
	tests := map[string]struct {
		artifact       []byte
		expectedChunks int
		matchString    string
	}{
		"png": {
			png,
			1,
			".*AKIAYVP4CIPPB4J6MWVQ.*",
		},
		"pdf": {
			pdf,
			1,
			".*AKIAYVP4CIPPB4J6MWVQ.*",
		},
		"rtf": {
			rtf,
			1,
			".*AKIAYVP4CIPPB4J6MWVQ.*",
		},
		"docx": {
			docx,
			1,
			".*AKIAYVP4CIPPB4J6MWVQ.*",
		},
		"odt": {
			odt,
			1,
			".*AKIAYVP4CIPPB4J6MWVQ.*",
		},
	}

	for name, testCase := range tests {
		tikaHandler := NewTika()
		tikaHandler.New()

		artifact := bytes.NewBuffer(testCase.artifact)

		newReader, err := diskbufferreader.New(artifact)
		if err != nil {
			t.Errorf("error creating reusable reader: %s", err)
		}
		chunks := tikaHandler.FromFile(newReader)

		count := 0
		re := regexp.MustCompile(testCase.matchString)
		matched := false
		for chunk := range chunks {
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

func TestTikaHandleFile(t *testing.T) {
	ch := make(chan *sources.Chunk, 2)

	// Context cancels the operation.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	file, err := diskbufferreader.New(strings.NewReader("file"))
	assert.NoError(t, err)
	assert.False(t, HandleFile(canceledCtx, file, &sources.Chunk{}, ch))

	artifact := bytes.NewBuffer(png)
	reader, err := diskbufferreader.New(artifact)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(ch))
	assert.True(t, HandleFile(context.Background(), reader, &sources.Chunk{}, ch))
	assert.Equal(t, 1, len(ch))
}
