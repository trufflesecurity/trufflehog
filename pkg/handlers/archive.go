package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/h2non/filetype"
	"github.com/mholt/archiver/v4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type ctxKey int

const (
	depthKey ctxKey = iota
)

var (
	maxDepth   = 5
	maxSize    = 250 * 1024 * 1024 // 20MB
	maxTimeout = time.Duration(30) * time.Second
)

// Ensure the Archive satisfies the interfaces at compile time.
var _ SpecializedHandler = (*Archive)(nil)

// Archive is a handler for extracting and decompressing archives.
type Archive struct {
	size int
}

// New sets a default maximum size and current size counter.
func (a *Archive) New() {
	a.size = 0
}

// SetArchiveMaxSize sets the maximum size of the archive.
func SetArchiveMaxSize(size int) {
	maxSize = size
}

// SetArchiveMaxDepth sets the maximum depth of the archive.
func SetArchiveMaxDepth(depth int) {
	maxDepth = depth
}

// SetArchiveMaxTimeout sets the maximum timeout for the archive handler.
func SetArchiveMaxTimeout(timeout time.Duration) {
	maxTimeout = timeout
}

// FromFile extracts the files from an archive.
func (a *Archive) FromFile(originalCtx context.Context, data io.Reader) chan ([]byte) {
	archiveChan := make(chan ([]byte), 512)
	go func() {
		ctx, cancel := context.WithTimeout(originalCtx, maxTimeout)
		logger := logContext.AddLogger(ctx).Logger()
		defer cancel()
		defer close(archiveChan)
		err := a.openArchive(ctx, 0, data, archiveChan)
		if err != nil {
			if errors.Is(err, archiver.ErrNoMatch) {
				return
			}
			logger.V(2).Info("Error unarchiving chunk.")
		}
	}()
	return archiveChan
}

// openArchive takes a reader and extracts the contents up to the maximum depth.
func (a *Archive) openArchive(ctx context.Context, depth int, reader io.Reader, archiveChan chan ([]byte)) error {
	if depth >= maxDepth {
		return fmt.Errorf("max archive depth reached")
	}
	format, reader, err := archiver.Identify("", reader)
	if err != nil {
		if errors.Is(err, archiver.ErrNoMatch) && depth > 0 {
			chunkSize := 10 * 1024
			for {
				chunk := make([]byte, chunkSize)
				n, _ := reader.Read(chunk)
				archiveChan <- chunk
				if n < chunkSize {
					break
				}
			}
			return nil
		}
		return err
	}
	switch archive := format.(type) {
	case archiver.Decompressor:
		compReader, err := archive.OpenReader(reader)
		if err != nil {
			return err
		}
		fileBytes, err := a.ReadToMax(ctx, compReader)
		if err != nil {
			return err
		}
		newReader := bytes.NewReader(fileBytes)
		return a.openArchive(ctx, depth+1, newReader, archiveChan)
	case archiver.Extractor:
		err := archive.Extract(context.WithValue(ctx, depthKey, depth+1), reader, nil, a.extractorHandler(archiveChan))
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("Unknown archive type: %s", format.Name())
}

// IsFiletype returns true if the provided reader is an archive.
func (a *Archive) IsFiletype(ctx context.Context, reader io.Reader) (io.Reader, bool) {
	format, readerB, err := archiver.Identify("", reader)
	if err != nil {
		return readerB, false
	}
	switch format.(type) {
	case archiver.Extractor:
		return readerB, true
	case archiver.Decompressor:
		return readerB, true
	}
	return readerB, false
}

// extractorHandler is applied to each file in an archiver.Extractor file.
func (a *Archive) extractorHandler(archiveChan chan ([]byte)) func(context.Context, archiver.File) error {
	return func(ctx context.Context, f archiver.File) error {
		logger := logContext.AddLogger(ctx).Logger()
		logger.V(5).Info("Handling extracted file.", "filename", f.Name())
		depth := 0
		if ctxDepth, ok := ctx.Value(depthKey).(int); ok {
			depth = ctxDepth
		}

		fReader, err := f.Open()
		if err != nil {
			return err
		}
		fileBytes, err := a.ReadToMax(ctx, fReader)
		if err != nil {
			return err
		}
		fileContent := bytes.NewReader(fileBytes)

		err = a.openArchive(ctx, depth, fileContent, archiveChan)
		if err != nil {
			return err
		}
		return nil
	}
}

// ReadToMax reads up to the max size.
func (a *Archive) ReadToMax(ctx context.Context, reader io.Reader) (data []byte, err error) {
	// Archiver v4 is in alpha and using an experimental version of
	// rardecode. There is a bug somewhere with rar decoder format 29
	// that can lead to a panic. An issue is open in rardecode repo
	// https://github.com/nwaples/rardecode/issues/30.
	logger := logContext.AddLogger(ctx).Logger()
	defer func() {
		if r := recover(); r != nil {
			// Return an error from ReadToMax.
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("Panic occurred: %v", r)
			}
			logger.Error(err, "Panic occurred when reading archive")
		}
	}()
	fileContent := bytes.Buffer{}
	logger.V(5).Info("Remaining buffer capacity", "bytes", maxSize-a.size)
	for i := 0; i <= maxSize/512; i++ {
		if common.IsDone(ctx) {
			return nil, ctx.Err()
		}
		fileChunk := make([]byte, 512)
		bRead, err := reader.Read(fileChunk)
		if err != nil && !errors.Is(err, io.EOF) {
			return []byte{}, err
		}
		a.size += bRead
		if len(fileChunk) > 0 {
			fileContent.Write(fileChunk[0:bRead])
		}
		if bRead < 512 {
			return fileContent.Bytes(), nil
		}
		if a.size >= maxSize && bRead == 512 {
			logger.V(2).Info("Max archive size reached.")
			return fileContent.Bytes(), nil
		}
	}
	return fileContent.Bytes(), nil
}

const (
	arMimeType  = "application/x-unix-archive"
	rpmMimeType = "application/x-rpm"
)

// HandleSpecialized takes a file path and an io.Reader representing the input file,
// and processes it based on its extension, such as handling Debian (.deb) and RPM (.rpm) packages.
// It returns an io.Reader that can be used to read the processed content of the file,
// and an error if any issues occurred during processing.
// The caller is responsible for closing the returned reader.
func (a *Archive) HandleSpecialized(ctx context.Context, reader io.Reader) (io.Reader, bool, error) {
	buffer := make([]byte, 512)
	n, err := reader.Read(buffer)
	if err != nil {
		return nil, false, fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	// Create a new reader that starts with the buffer we just read
	// and continues with the rest of the original reader.
	reader = io.MultiReader(bytes.NewReader(buffer[:n]), reader)

	kind, err := filetype.Match(buffer)
	if err != nil {
		return nil, false, fmt.Errorf("unable to determine file type: %w", err)
	}

	switch mimeType := kind.MIME.Value; mimeType {
	case arMimeType: // includes .deb files
		reader, err = extractDebContent(ctx, reader)
	case rpmMimeType:
		reader, err = extractRpmContent(ctx, reader)
	default:
		return reader, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("unable to extract file with MIME type %s: %w", kind.MIME.Value, err)
	}
	return reader, true, nil
}

// extractDebContent takes a .deb file as an io.Reader, extracts its contents
// into a temporary directory, and returns a Reader for the extracted data archive.
// It handles the extraction process by using the 'ar' command and manages temporary
// files and directories for the operation.
// The caller is responsible for closing the returned reader.
func extractDebContent(_ context.Context, file io.Reader) (io.ReadCloser, error) {
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

	// Determine the correct data archive name. (e.g., data.tar.gz, data.tar.xz)
	var dataArchiveName string
	for _, file := range extractedFiles {
		if strings.HasPrefix(file.Name(), "data.tar.") {
			dataArchiveName = file.Name() // Use the actual name if different
			break
		}
	}

	return openDataArchive(tempEnv.extractPath, dataArchiveName)
}

// extractRpmContent takes an .rpm file as an io.Reader, extracts its contents
// into a temporary directory, and returns a Reader for the extracted data archive.
// It handles the extraction process by using the 'rpm2cpio' and 'cpio' commands and manages temporary
// files and directories for the operation.
// The caller is responsible for closing the returned reader.
func extractRpmContent(_ context.Context, file io.Reader) (io.ReadCloser, error) {
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
func createTempEnv(file io.Reader) (tempEnv, error) {
	tempFile, err := os.CreateTemp("", "tmp")
	if err != nil {
		return tempEnv{}, fmt.Errorf("unable to create temporary file: %w", err)
	}

	extractPath, err := os.MkdirTemp("", "tmp_archive")
	if err != nil {
		return tempEnv{}, fmt.Errorf("unable to create temporary directory: %w", err)
	}

	if _, err = io.Copy(tempFile, file); err != nil {
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
