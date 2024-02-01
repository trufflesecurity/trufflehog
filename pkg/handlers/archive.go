package handlers

import (
	"bufio"
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

	"github.com/gabriel-vasile/mimetype"
	"github.com/h2non/filetype"
	"github.com/mholt/archiver/v4"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type ctxKey int

const (
	depthKey ctxKey = iota

	errMaxArchiveDepthReached = "max archive depth reached"
)

var (
	maxDepth   = 5
	maxSize    = 250 * 1024 * 1024 // 20MB
	maxTimeout = time.Duration(30) * time.Second

	defaultBufferSize = 512
)

// Ensure the Archive satisfies the interfaces at compile time.
var _ SpecializedHandler = (*Archive)(nil)

// Archive is a handler for extracting and decompressing archives.
type Archive struct {
	size         int
	currentDepth int
	skipBinaries bool
	skipArchives bool
}

// New creates a new Archive handler with the provided options.
func (a *Archive) New(opts ...Option) {
	for _, opt := range opts {
		opt(a)
	}
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
func (a *Archive) FromFile(originalCtx logContext.Context, data io.Reader) chan []byte {
	if a.skipArchives {
		return nil
	}

	archiveChan := make(chan []byte, defaultBufferSize)
	go func() {
		ctx, cancel := logContext.WithTimeout(originalCtx, maxTimeout)
		logger := logContext.AddLogger(ctx).Logger()
		defer cancel()
		defer close(archiveChan)
		err := a.openArchive(ctx, 0, data, archiveChan)
		if err != nil {
			if errors.Is(err, archiver.ErrNoMatch) {
				return
			}
			logger.Error(err, "error unarchiving chunk.")
		}
	}()
	return archiveChan
}

// openArchive takes a reader and extracts the contents up to the maximum depth.
func (a *Archive) openArchive(ctx logContext.Context, depth int, reader io.Reader, archiveChan chan []byte) error {
	if common.IsDone(ctx) {
		return ctx.Err()
	}

	if depth >= maxDepth {
		return fmt.Errorf(errMaxArchiveDepthReached)
	}

	format, arReader, err := archiver.Identify("", reader)
	if errors.Is(err, archiver.ErrNoMatch) && depth > 0 {
		return a.handleNonArchiveContent(ctx, arReader, archiveChan)
	}

	if err != nil {
		return err
	}

	switch archive := format.(type) {
	case archiver.Decompressor:
		// Decompress tha archive and feed the decompressed data back into the archive handler to extract any nested archives.
		compReader, err := archive.OpenReader(arReader)
		if err != nil {
			return err
		}

		defer compReader.Close()

		return a.openArchive(ctx, depth+1, compReader, archiveChan)
	case archiver.Extractor:
		return archive.Extract(logContext.WithValue(ctx, depthKey, depth+1), arReader, nil, a.extractorHandler(archiveChan))
	default:
		return fmt.Errorf("unknown archive type: %s", format.Name())
	}
}

const mimeTypeBufferSize = 512

func (a *Archive) handleNonArchiveContent(ctx logContext.Context, reader io.Reader, archiveChan chan []byte) error {
	bufReader := bufio.NewReaderSize(reader, mimeTypeBufferSize)
	// A buffer of 512 bytes is used since many file formats store their magic numbers within the first 512 bytes.
	// If fewer bytes are read, MIME type detection may still succeed.
	buffer, err := bufReader.Peek(mimeTypeBufferSize)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	mime := mimetype.Detect(buffer)
	mimeT := mimeType(mime.String())

	if common.SkipFile(mime.Extension()) {
		ctx.Logger().V(5).Info("skipping file", "ext", mimeT)
		return nil
	}

	if a.skipBinaries {
		if common.IsBinary(mime.Extension()) || mimeT == machOType || mimeT == octetStream {
			ctx.Logger().V(5).Info("skipping binary file", "ext", mimeT)
			return nil
		}
	}

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, bufReader)
	for data := range chunkResChan {
		if err := data.Error(); err != nil {
			ctx.Logger().Error(err, "error reading chunk")
			continue
		}
		if err := common.CancellableWrite(ctx, archiveChan, data.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// IsFiletype returns true if the provided reader is an archive.
func (a *Archive) IsFiletype(_ logContext.Context, reader io.Reader) (io.Reader, bool) {
	format, readerB, err := archiver.Identify("", reader)
	if err != nil {
		return readerB, false
	}
	switch format.(type) {
	case archiver.Extractor:
		return readerB, true
	case archiver.Decompressor:
		return readerB, true
	default:
		return readerB, false
	}
}

// extractorHandler is applied to each file in an archiver.Extractor file.
func (a *Archive) extractorHandler(archiveChan chan []byte) func(context.Context, archiver.File) error {
	return func(ctx context.Context, f archiver.File) error {
		lCtx := logContext.AddLogger(ctx)
		lCtx.Logger().V(5).Info("Handling extracted file.", "filename", f.Name())

		if common.IsDone(ctx) {
			return ctx.Err()
		}

		depth := 0
		if ctxDepth, ok := ctx.Value(depthKey).(int); ok {
			depth = ctxDepth
		}

		fReader, err := f.Open()
		if err != nil {
			return err
		}
		defer fReader.Close()

		if common.SkipFile(f.Name()) {
			lCtx.Logger().V(5).Info("skipping file", "filename", f.Name())
			return nil
		}

		if a.skipBinaries && common.IsBinary(f.Name()) {
			lCtx.Logger().V(5).Info("skipping binary file", "filename", f.Name())
			return nil
		}

		return a.openArchive(lCtx, depth, fReader, archiveChan)
	}
}

// ReadToMax reads up to the max size.
func (a *Archive) ReadToMax(ctx logContext.Context, reader io.Reader) (data []byte, err error) {
	// Archiver v4 is in alpha and using an experimental version of
	// rardecode. There is a bug somewhere with rar decoder format 29
	// that can lead to a panic. An issue is open in rardecode repo
	// https://github.com/nwaples/rardecode/issues/30.
	defer func() {
		if r := recover(); r != nil {
			// Return an error from ReadToMax.
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("panic occurred: %v", r)
			}
			ctx.Logger().Error(err, "Panic occurred when reading archive")
		}
	}()

	if common.IsDone(ctx) {
		return nil, ctx.Err()
	}

	var fileContent bytes.Buffer
	// Create a limited reader to ensure we don't read more than the max size.
	lr := io.LimitReader(reader, int64(maxSize))

	// Using io.CopyBuffer for performance advantages. Though buf is mandatory
	// for the method, due to the internal implementation of io.CopyBuffer, when
	// *bytes.Buffer implements io.WriterTo or io.ReaderFrom, the provided buf
	// is simply ignored. Thus, we can pass nil for the buf parameter.
	_, err = io.CopyBuffer(&fileContent, lr, nil)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if fileContent.Len() == maxSize {
		ctx.Logger().V(2).Info("Max archive size reached.")
	}

	return fileContent.Bytes(), nil
}

type mimeType string

const (
	arMimeType  mimeType = "application/x-unix-archive"
	rpmMimeType mimeType = "application/x-rpm"
	machOType   mimeType = "application/x-mach-binary"
	octetStream mimeType = "application/octet-stream"
)

// mimeTools maps MIME types to the necessary command-line tools to handle them.
// This centralizes the tool requirements for different file types.
var mimeTools = map[mimeType][]string{
	arMimeType:  {"ar"},
	rpmMimeType: {"rpm2cpio", "cpio"},
}

// extractToolCache stores the availability of extraction tools, eliminating the need for repeated filesystem lookups.
var extractToolCache map[string]bool

func init() {
	// Preload the extractToolCache with the availability status of each required tool.
	extractToolCache = make(map[string]bool)
	for _, tools := range mimeTools {
		for _, tool := range tools {
			_, err := exec.LookPath(tool)
			extractToolCache[tool] = err == nil
		}
	}
}

func ensureToolsForMimeType(mimeType mimeType) error {
	tools, exists := mimeTools[mimeType]
	if !exists {
		return fmt.Errorf("unsupported mime type: %s", mimeType)
	}

	for _, tool := range tools {
		if installed := extractToolCache[tool]; !installed {
			return fmt.Errorf("required tool %s is not installed", tool)
		}
	}
	return nil
}

// HandleSpecialized takes a file path and an io.Reader representing the input file,
// and processes it based on its extension, such as handling Debian (.deb) and RPM (.rpm) packages.
// It returns an io.Reader that can be used to read the processed content of the file,
// and an error if any issues occurred during processing.
// If the file is specialized, the returned boolean is true with no error.
// The caller is responsible for closing the returned reader.
func (a *Archive) HandleSpecialized(ctx logContext.Context, reader io.Reader) (io.Reader, bool, error) {
	mimeType, reader, err := determineMimeType(reader)
	if err != nil {
		return nil, false, err
	}

	switch mimeType {
	case arMimeType: // includes .deb files
		if err := ensureToolsForMimeType(mimeType); err != nil {
			return nil, false, err
		}
		reader, err = a.extractDebContent(ctx, reader)
	case rpmMimeType:
		if err := ensureToolsForMimeType(mimeType); err != nil {
			return nil, false, err
		}
		reader, err = a.extractRpmContent(ctx, reader)
	default:
		return reader, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("unable to extract file with MIME type %s: %w", mimeType, err)
	}
	return reader, true, nil
}

// extractDebContent takes a .deb file as an io.Reader, extracts its contents
// into a temporary directory, and returns a Reader for the extracted data archive.
// It handles the extraction process by using the 'ar' command and manages temporary
// files and directories for the operation.
// The caller is responsible for closing the returned reader.
func (a *Archive) extractDebContent(ctx logContext.Context, file io.Reader) (io.ReadCloser, error) {
	if a.currentDepth >= maxDepth {
		return nil, fmt.Errorf(errMaxArchiveDepthReached)
	}

	tmpEnv, err := a.createTempEnv(ctx, file)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpEnv.tempFileName)
	defer os.RemoveAll(tmpEnv.extractPath)

	cmd := exec.Command("ar", "x", tmpEnv.tempFile.Name())
	cmd.Dir = tmpEnv.extractPath
	if err := executeCommand(cmd); err != nil {
		return nil, err
	}

	handler := func(ctx logContext.Context, env tempEnv, file string) (string, error) {
		if strings.HasPrefix(file, "data.tar.") {
			return file, nil
		}
		return a.handleNestedFileMIME(ctx, env, file)
	}

	dataArchiveName, err := a.handleExtractedFiles(ctx, tmpEnv, handler)
	if err != nil {
		return nil, err
	}

	return openDataArchive(tmpEnv.extractPath, dataArchiveName)
}

// extractRpmContent takes an .rpm file as an io.Reader, extracts its contents
// into a temporary directory, and returns a Reader for the extracted data archive.
// It handles the extraction process by using the 'rpm2cpio' and 'cpio' commands and manages temporary
// files and directories for the operation.
// The caller is responsible for closing the returned reader.
func (a *Archive) extractRpmContent(ctx logContext.Context, file io.Reader) (io.ReadCloser, error) {
	if a.currentDepth >= maxDepth {
		return nil, fmt.Errorf("max archive depth reached")
	}

	tmpEnv, err := a.createTempEnv(ctx, file)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpEnv.tempFileName)
	defer os.RemoveAll(tmpEnv.extractPath)

	// Use rpm2cpio to convert the RPM file to a cpio archive and then extract it using cpio command.
	cmd := exec.Command("sh", "-c", "rpm2cpio "+tmpEnv.tempFile.Name()+" | cpio -id")
	cmd.Dir = tmpEnv.extractPath
	if err := executeCommand(cmd); err != nil {
		return nil, err
	}

	handler := func(ctx logContext.Context, env tempEnv, file string) (string, error) {
		if strings.HasSuffix(file, ".tar.gz") {
			return file, nil
		}
		return a.handleNestedFileMIME(ctx, env, file)
	}

	dataArchiveName, err := a.handleExtractedFiles(ctx, tmpEnv, handler)
	if err != nil {
		return nil, err
	}

	return openDataArchive(tmpEnv.extractPath, dataArchiveName)
}

func (a *Archive) handleNestedFileMIME(ctx logContext.Context, tempEnv tempEnv, fileName string) (string, error) {
	nestedFile, err := os.Open(filepath.Join(tempEnv.extractPath, fileName))
	if err != nil {
		return "", err
	}
	defer nestedFile.Close()

	mimeType, reader, err := determineMimeType(nestedFile)
	if err != nil {
		return "", fmt.Errorf("unable to determine MIME type of nested filename: %s, %w", nestedFile.Name(), err)
	}

	switch mimeType {
	case arMimeType, rpmMimeType:
		_, _, err = a.HandleSpecialized(ctx, reader)
	default:
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("unable to extract file with MIME type %s: %w", mimeType, err)
	}

	return fileName, nil
}

// determineMimeType reads from the provided reader to detect the MIME type.
// It returns the detected MIME type and a new reader that includes the read portion.
func determineMimeType(reader io.Reader) (mimeType, io.Reader, error) {
	// A buffer of 512 bytes is used since many file formats store their magic numbers within the first 512 bytes.
	// If fewer bytes are read, MIME type detection may still succeed.
	buffer := make([]byte, 512)
	n, err := reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", nil, fmt.Errorf("unable to read file for MIME type detection: %w", err)
	}

	// Create a new reader that starts with the buffer we just read
	// and continues with the rest of the original reader.
	reader = io.MultiReader(bytes.NewReader(buffer[:n]), reader)

	kind, err := filetype.Match(buffer)
	if err != nil {
		return "", nil, fmt.Errorf("unable to determine file type: %w", err)
	}

	return mimeType(kind.MIME.Value), reader, nil
}

// handleExtractedFiles processes each file in the extracted directory using a provided handler function.
// The function iterates through the files, applying the handleFile function to each, and returns the name
// of the data archive it finds. This centralizes the logic for handling specialized files such as .deb and .rpm
// by using the appropriate handling function passed as an argument. This design allows for flexibility and reuse
// of this function across various extraction processes in the package.
func (a *Archive) handleExtractedFiles(ctx logContext.Context, env tempEnv, handleFile func(logContext.Context, tempEnv, string) (string, error)) (string, error) {
	extractedFiles, err := os.ReadDir(env.extractPath)
	if err != nil {
		return "", fmt.Errorf("unable to read extracted directory: %w", err)
	}

	var dataArchiveName string
	for _, file := range extractedFiles {
		filename := file.Name()
		filePath := filepath.Join(env.extractPath, filename)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return "", fmt.Errorf("unable to get file info for filename %s: %w", filename, err)
		}
		if fileInfo.IsDir() {
			continue
		}

		name, err := handleFile(ctx, env, filename)
		if err != nil {
			return "", err
		}
		if name != "" {
			dataArchiveName = name
			break
		}
	}

	return dataArchiveName, nil
}

type tempEnv struct {
	tempFile     *os.File
	tempFileName string
	extractPath  string
}

// createTempEnv creates a temporary file and a temporary directory for extracting archives.
// The caller is responsible for removing these temporary resources
// (both the file and directory) when they are no longer needed.
func (a *Archive) createTempEnv(ctx logContext.Context, file io.Reader) (tempEnv, error) {
	tempFile, err := os.CreateTemp("", "tmp")
	if err != nil {
		return tempEnv{}, fmt.Errorf("unable to create temporary file: %w", err)
	}

	extractPath, err := os.MkdirTemp("", "tmp_archive")
	if err != nil {
		return tempEnv{}, fmt.Errorf("unable to create temporary directory: %w", err)
	}

	b, err := a.ReadToMax(ctx, file)
	if err != nil {
		return tempEnv{}, err
	}

	if _, err = tempFile.Write(b); err != nil {
		return tempEnv{}, fmt.Errorf("unable to write to temporary file: %w", err)
	}

	return tempEnv{tempFile: tempFile, tempFileName: tempFile.Name(), extractPath: extractPath}, nil
}

func executeCommand(cmd *exec.Cmd) error {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to execute command %v: %w; error: %s", cmd.String(), err, stderr.String())
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
