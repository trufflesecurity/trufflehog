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
		reader, err = extractRpmContent(ctx, inputFile)
	default:
		reader = inputFile
	}
	if err != nil {
		return nil, fmt.Errorf("unable to extract file with extension %s: %w", ext, err)
	}
	return reader, nil
}

// extractDebContent takes a .deb file as an io.ReadCloser, extracts its contents
// into a temporary directory, and returns a ReadCloser for the extracted data archive.
// It handles the extraction process by using the 'ar' command and manages temporary
// files and directories for the operation.
// The caller is responsible for closing the returned reader.
func extractDebContent(_ logContext.Context, file io.ReadCloser) (io.ReadCloser, error) {
	tempEnv, err := createTempEnv(file)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempEnv.tempFileName)
	defer os.RemoveAll(tempEnv.extractPath)

	cmd := exec.Command("ar", "x", tempEnv.tempFile.Name())
	cmd.Dir = tempEnv.extractPath
	if err := executeCommand(cmd); err != nil {
		return nil, err
	}

	// List the content of the extraction directory.
	extractedFiles, err := os.ReadDir(tempEnv.extractPath)
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

	return openDataArchive(tempEnv.extractPath, dataArchiveName)
}

// extractRpmContent takes an .rpm file as an io.ReadCloser, extracts its contents
// into a temporary directory, and returns a ReadCloser for the extracted data archive.
// It handles the extraction process by using the 'rpm2cpio' and 'cpio' commands and manages temporary
// files and directories for the operation.
// The caller is responsible for closing the returned reader.
func extractRpmContent(ctx logContext.Context, file io.ReadCloser) (io.ReadCloser, error) {
	tempEnv, err := createTempEnv(file)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempEnv.tempFileName)
	defer os.RemoveAll(tempEnv.extractPath)

	// Use rpm2cpio to convert the RPM file to a cpio archive and then extract it using cpio command.
	cmd := exec.Command("sh", "-c", "rpm2cpio "+tempEnv.tempFile.Name()+" | cpio -id")
	cmd.Dir = tempEnv.extractPath
	if err := executeCommand(cmd); err != nil {
		return nil, err
	}

	// List the content of the extraction directory.
	extractedFiles, err := os.ReadDir(tempEnv.extractPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read extracted directory: %w", err)
	}

	var dataArchiveName string
	// Determine the correct data archive name.
	for _, file := range extractedFiles {
		if strings.HasSuffix(file.Name(), ".tar.gz") {
			dataArchiveName = file.Name()
			break
		}
	}

	return openDataArchive(tempEnv.extractPath, dataArchiveName)
}

type tempEnv struct {
	tempFile     *os.File
	tempFileName string
	extractPath  string
}

// createTempEnv creates a temporary file and a temporary directory for extracting archives.
// The caller is responsible for removing these temporary resources
// (both the file and directory) when they are no longer needed.
func createTempEnv(file io.ReadCloser) (tempEnv, error) {
	tempFile, err := os.CreateTemp("", "tmp")
	if err != nil {
		return tempEnv{}, fmt.Errorf("unable to create temporary file: %w", err)
	}

	extractPath, err := os.MkdirTemp("", "tmp_archive")
	if err != nil {
		return tempEnv{}, fmt.Errorf("unable to create temporary directory: %w", err)
	}

	_, err = io.Copy(tempFile, file)
	if err != nil {
		return tempEnv{}, fmt.Errorf("unable to copy content to temporary file: %w", err)
	}

	return tempEnv{tempFile: tempFile, tempFileName: tempFile.Name(), extractPath: extractPath}, nil
}

func executeCommand(cmd *exec.Cmd) error {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to execute command: %w; error: %s", err, stderr.String())
	}
	return nil
}

func openDataArchive(extractPath string, dataArchiveName string) (io.ReadCloser, error) {
	dataArchivePath := filepath.Join(extractPath, dataArchiveName)
	dataFile, err := os.Open(dataArchivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}
	return dataFile, nil
}
