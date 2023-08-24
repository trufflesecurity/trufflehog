//go:build integration
// +build integration

package handlers

import (
	"context"
	"os"
	"testing"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/assert"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestFoundKeyInDockerTar(t *testing.T) {
	// URI of the Docker image to clone
	// imageURI := "ghcr.io/joeleonjr/getting-started-app-with-canary-token:main"
	imageURI := "trufflesecurity/secrets"

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

	ctx := logContext.AddLogger(context.Background())

	inputFile, err := os.Open(tempFile.Name())
	if err != nil {
		t.Errorf("%s: error opening tar file: %s", imageURI, err)
		return
	}
	defer inputFile.Close()

	reReader, err := diskbufferreader.New(inputFile)
	if err != nil {
		t.Errorf("%s: error creating re-readable reader: %s", imageURI, err)
		return
	}
	defer reReader.Close()

	chunkSkel := &sources.Chunk{
		SourceType: 1,
		SourceName: "filesystem",
		SourceID:   1,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Filesystem{
				Filesystem: &source_metadatapb.Filesystem{
					File: sanitizer.UTF8(tempFile.Name()),
				},
			},
		},
		Verify: true,
	}

	chunksChan := make(chan *sources.Chunk, 1)

	go func() {
		defer close(chunksChan)
		HandleFile(ctx, reReader, chunkSkel, chunksChan)
	}()

	secret := "AKIA2OGYBAH6Q2PQJUGN"

	// Read from the channel and validate the secrets.
	foundSecret := ""
	for chunkCh := range chunksChan {
		foundSecret += string(chunkCh.Data)
	}

	assert.Contains(t, foundSecret, secret)

}
