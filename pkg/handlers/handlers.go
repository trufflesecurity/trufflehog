package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
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

func HandleFile(ctx context.Context, file io.Reader, chunkSkel *sources.Chunk, chunksChan chan *sources.Chunk) bool {
	// Find a handler for this file.
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

const (
	debFileExtension = ".deb"
	rpmFileExtension = ".rpm"
)

// HandleSpecializedArchives takes a file path and an io.ReadCloser representing the input file,
// and processes it based on its extension, such as handling Debian (.deb) and RPM (.rpm) packages.
// It returns an io.ReadCloser that can be used to read the processed content of the file,
// and an error if any issues occurred during processing.
// The caller is responsible for closing the returned reader.
func HandleSpecializedArchives(ctx logContext.Context, path string, inputFile io.ReadCloser) (io.ReadCloser, error) {
	var reader io.ReadCloser
	var err error
	ext := filepath.Ext(path)
	switch ext {
	case debFileExtension:
		reader, err = extractDebContent(ctx, inputFile)
	case rpmFileExtension:
		// TODO: Implement RPM extraction.
	default:
		reader = inputFile
	}
	if err != nil {
		return nil, fmt.Errorf("unable to extract file with extension %s: %w", ext, err)
	}
	return reader, nil
}

// extractDebContent takes a .deb file as an io.Reader, extracts its contents
// into a temporary directory, and returns a reader for the extracted data archive.
// It handles the extraction process by using the 'ar' command and manages temporary
// files and directories for the operation.
// The caller is responsible for closing the returned reader.
func extractDebContent(ctx logContext.Context, file io.Reader) (io.ReadCloser, error) {
	// Create a temporary file to write the .deb content.
	tempFile, err := os.CreateTemp("", "debfile")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = io.Copy(tempFile, file)
	if err != nil {
		return nil, fmt.Errorf("unable to handle temporary file: %w", err)
	}
	tempFile.Close()

	extractPath, err := os.MkdirTemp("", "deb_extract")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary directory: %w", err)
	}
	defer os.RemoveAll(extractPath)

	cmd := exec.Command("ar", "x", tempFile.Name())
	cmd.Dir = extractPath
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("unable to extract .deb file: %w; ar error: %s", err, stderr.String())
	}

	// List the content of the extraction directory.
	extractedFiles, err := os.ReadDir(extractPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read extracted directory: %w", err)
	}

	const defaultDataArchiveName = "data.tar.gz"

	// Determine the correct data archive name. (e.g., data.tar.gz, data.tar.xz)
	dataArchiveName := defaultDataArchiveName
	for _, file := range extractedFiles {
		if strings.HasPrefix(file.Name(), "data.tar.") {
			dataArchiveName = file.Name() // Use the actual name if different
			break
		}
	}

	dataArchivePath := filepath.Join(extractPath, dataArchiveName)
	dataFile, err := os.Open(dataArchivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}
	return dataFile, nil
}
