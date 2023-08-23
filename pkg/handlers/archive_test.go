package handlers

import (
	"context"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/stretchr/testify/assert"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
		archiveChan := archive.FromFile(context.Background(), newReader)

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
	ctx := logContext.AddLogger(context.Background())
	canceledCtx, cancel := logContext.WithCancel(ctx)
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
	assert.True(t, HandleFile(ctx, reader, &sources.Chunk{}, ch))
	assert.Equal(t, 1, len(ch))
}

func TestExtractDebContent(t *testing.T) {
	// Open the sample .deb file from the testdata folder.
	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)
	defer file.Close()

	ctx := logContext.AddLogger(context.Background())
	a := &Archive{}

	reader, err := a.extractDebContent(ctx, file)
	assert.Nil(t, err)

	content, err := io.ReadAll(reader)
	assert.Nil(t, err)
	expectedLength := 1015582
	assert.Equal(t, expectedLength, len(string(content)))
}

func TestExtractTarContent(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)
	defer file.Close()

	ctx := logContext.AddLogger(context.Background())

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		ok := HandleFile(ctx, file, &sources.Chunk{}, chunkCh)
		assert.True(t, ok)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestExtractRPMContent(t *testing.T) {
	// Open the sample .rpm file from the testdata folder.
	file, err := os.Open("testdata/test.rpm")
	assert.Nil(t, err)
	defer file.Close()

	ctx := logContext.AddLogger(context.Background())
	a := &Archive{}

	reader, err := a.extractRpmContent(ctx, file)
	assert.Nil(t, err)

	content, err := io.ReadAll(reader)
	assert.Nil(t, err)
	expectedLength := 1822720
	assert.Equal(t, expectedLength, len(string(content)))
}

func TestFoundKeyInDockerTar(t *testing.T) {
	// URI of the Docker image to clone
	imageURI := "ghcr.io/joeleonjr/getting-started-app-with-canary-token:main"

	var imageName name.Reference
	imageName, err := name.NewTag(imageURI)
	if err != nil {
		t.Errorf("%s: error creating image name: %s", imageURI, err)
	}

	// Pull the image
	img, err := remote.Image(imageName)
	if err != nil {
		t.Errorf("%s: error pulling image: %s", imageURI, err)
	}

	tempFile, err := os.CreateTemp("", "archive_test_docker_img.tar")
	if err != nil {
		t.Errorf("%s: error creating temporary file: %s", imageURI, err)
		return
	}

	defer os.Remove(tempFile.Name()) // Clean up the temporary file

	// Save the image as a tar file
	err = tarball.WriteToFile(tempFile.Name(), imageName, img)
	if err != nil {
		t.Errorf("%s: error saving image as tar file: %s", imageURI, err)
		return
	}

	// ctx := logContext.AddLogger(context.Background())

	// inputFile, err := os.Open(tempFile.Name())
	// if err != nil {
	// 	t.Errorf("%s: error opening tar file: %s", imageURI, err)
	// 	return
	// }
	// defer inputFile.Close()

	// reReader, err := diskbufferreader.New(inputFile)
	// if err != nil {
	// 	t.Errorf("%s: error creating re-readable reader: %s", imageURI, err)
	// 	return
	// }
	// defer reReader.Close()

	// chunkSkel := &sources.Chunk{
	// 	SourceType: 1,
	// 	SourceName: "filesystem",
	// 	SourceID:   1,
	// 	SourceMetadata: &source_metadatapb.MetaData{
	// 		Data: &source_metadatapb.MetaData_Filesystem{
	// 			Filesystem: &source_metadatapb.Filesystem{
	// 				File: sanitizer.UTF8(tempFile.Name()),
	// 			},
	// 		},
	// 	},
	// 	Verify: true,
	// }

	// chunksChan := make(chan *sources.Chunk, 1)

	// HandleFile(ctx, reReader, chunkSkel, chunksChan)

	// println("here")
	// fmt.Printf("chunksChan: %v\n", chunksChan)
	// fmt.Printf("chunksChan: %v\n", &chunksChan)

	// secret := "AKIA2OGYBAH6Q2PQJUGN"

	// // Read from the channel and validate the secrets.
	// foundSecret := ""
	// for chunkCh := range chunksChan {
	// 	foundSecret += string(chunkCh.Data)
	// }

	// assert.Contains(t, foundSecret, secret)

}
