package handlers

import (
	"context"
	"io"
	"runtime"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

// SpecializedHandler defines the interface for handlers that can process specialized archives.
// It includes a method to handle specialized archives and determine if the file is of a special type.
type SpecializedHandler interface {
	// HandleSpecialized examines the provided file reader within the context and determines if it is a specialized archive.
	// It returns a reader with any necessary modifications, a boolean indicating if the file was specialized,
	// and an error if something went wrong during processing.
	HandleSpecialized(logContext.Context, io.Reader) (io.Reader, bool, error)
}

type Handler interface {
	FromFile(context.Context, io.Reader) chan []byte
	IsFiletype(context.Context, io.Reader) (io.Reader, bool)
	New()
}

// HandleFile processes a given file by selecting an appropriate handler from DefaultHandlers.
// It first checks if the handler implements SpecializedHandler for any special processing,
// then falls back to regular file type handling. If successful, it reads the file in chunks,
// packages them in the provided chunk skeleton, and sends them to chunksChan.
// The function returns true if processing was successful and false otherwise.
// Context is used for cancellation, and the caller is responsible for canceling it if needed.
func HandleFile(ctx logContext.Context, file io.Reader, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	aCtx := logContext.AddLogger(ctx)
	for _, h := range DefaultHandlers() {
		h.New()

		// The re-reader is used to reset the file reader after checking if the handler implements SpecializedHandler.
		// This is necessary because the archive pkg doesn't correctly determine the file type when using
		// an io.MultiReader, which is used by the SpecializedHandler.
		reReader, err := diskbufferreader.New(file)
		if err != nil {
			aCtx.Logger().Error(err, "error creating re-reader reader")
			return false
		}
		defer reReader.Close()

		// Check if the handler implements SpecializedHandler and process accordingly.
		if specialHandler, ok := h.(SpecializedHandler); ok {
			file, isSpecial, err := specialHandler.HandleSpecialized(aCtx, reReader)
			if isSpecial {
				if dockerTarReader, ok := file.(DockerTarReader); ok {
					return handleDockerTar(ctx, dockerTarReader.filepath, chunkSkel, chunksChan)
				}
				return handleChunks(aCtx, h.FromFile(ctx, file), chunkSkel, chunksChan)
			}
			if err != nil {
				aCtx.Logger().Error(err, "error handling file")
			}
		}

		if err := reReader.Reset(); err != nil {
			aCtx.Logger().Error(err, "error resetting re-reader")
			return false
		}
		if _, isType := h.IsFiletype(aCtx, reReader); !isType {
			continue
		}

		if err := reReader.Reset(); err != nil {
			aCtx.Logger().Error(err, "error resetting re-reader")
			return false
		}
		reReader.Stop()
		return handleChunks(aCtx, h.FromFile(ctx, reReader), chunkSkel, chunksChan)
	}

	return false
}

func handleChunks(ctx context.Context, handlerChan chan []byte, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	for {
		select {
		case data, open := <-handlerChan:
			if !open {
				return true
			}
			chunk := *chunkSkel
			chunk.Data = data
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

func handleDockerTar(ctx logContext.Context, filePath string, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	// aCtx := logContext.AddLogger(ctx)
	// aCtx.logger.V(3).Info("Docker image detected in tarball: " + filePath)
	//scan with docker scanner
	dockerConn := sourcespb.Docker{
		Images: []string{"file://" + filePath},
		Credential: &sourcespb.Docker_DockerKeychain{
			DockerKeychain: true,
		},
	}
	anyConn, err := anypb.New(&dockerConn)
	if err != nil {
		// aCtx.logger.V(3).Info("error marshalling Docker connection", "error", err)
		return false
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
