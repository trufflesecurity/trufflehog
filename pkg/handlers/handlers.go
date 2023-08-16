package handlers

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"

	"github.com/google/go-containerregistry/pkg/v1/tarball"
	context2 "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/docker"
	"google.golang.org/protobuf/types/known/anypb"
)

func DefaultHandlers() []Handler {
	return []Handler{
		&Archive{},
	}
}

type Handler interface {
	FromFile(context.Context, io.Reader) chan ([]byte)
	IsFiletype(context.Context, io.Reader) (io.Reader, bool)
	New()
}

func HandleFile(ctx context2.Context, file io.Reader, chunkSkel *sources.Chunk, chunksChan chan (*sources.Chunk)) bool {

	var handler Handler
	for _, h := range DefaultHandlers() {
		h.New()
		var isType bool
		if file, isType = h.IsFiletype(ctx, file); isType {
			handler = h
			break
		}
	}
	if handler == nil {
		return false
	}

	if IsReaderTarball(ctx, file) {
		isDocker, path := IsDockerImage(ctx, file)
		if isDocker {
			// if docker image then run
			ctx.logger.V(3).Info("Docker image detected in tarball: " + path)
			//scan with docker scanner
			dockerConn := sourcespb.Docker{
				Images: []string{"file://" + path},
				Credential: &sourcespb.Docker_DockerKeychain{
					DockerKeychain: true,
				},
			}
			anyConn, err := anypb.New(&dockerConn)
			if err != nil {
				ctx.logger.V(3).Info("error marshalling Docker connection", "error", err)
			}
			dockerSource := docker.Source{}
			if err := dockerSource.Init(ctx, "trufflehog - docker", 0, chunkSkel.SourceID, chunkSkel.Verify, anyConn, runtime.NumCPU()); err != nil {
				// will need to pas this in later s.jobId
				return false
			}
			if err := dockerSource.Chunks(ctx, chunksChan); err != nil {
				return false
			}
			return true
		}
	}

	// Process the file and read all []byte chunks from handlerChan.
	handlerChan := handler.FromFile(ctx, file)
	for {
		select {
		case data, open := <-handlerChan:
			if !open {
				// We finished reading everything from handlerChan.
				return true
			}
			chunk := *chunkSkel
			chunk.Data = data
			// Send data on chunksChan.
			select {
			case chunksChan <- &chunk:
			case <-ctx.Done():
				return false
			}
		case <-ctx.Done():
			return false
		}
	}
}

func IsReaderTarball(ctx context2.Context, reader io.Reader) bool {
	// Check if file is a tarball, if so, check if it is a Docker image.
	_, err := tar.NewReader(reader).Next()
	if err != nil {
		return false
	}
	return true
}

func IsDockerImage(ctx context2.Context, file io.Reader) (isDocker bool, tmpFilename string) {
	// Generate a random name for the temporary file.
	tmpFilename = fmt.Sprintf("%s/temp_%d.tar", os.TempDir(), rand.Int())

	// Create a temporary file to write image data from ReadCloser.
	tmpFile, err := os.Create(tmpFilename)
	if err != nil {
		fmt.Printf("Error creating temporary file: %s\n", err)
		return false, ""
	}
	defer os.Remove(tmpFilename)

	// Copy data from ReadCloser to the temporary file.
	if _, err := io.Copy(tmpFile, file); err != nil {
		fmt.Printf("Error copying data to temporary file: %s\n", err)
		return false, ""
	}
	tmpFile.Close()

	_, err = tarball.ImageFromPath(tmpFilename, nil)
	if err != nil {
		return false, ""
	}
	return true, tmpFilename
}
