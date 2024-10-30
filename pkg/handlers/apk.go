package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	dextk "github.com/csnewman/dextk"

	"github.com/avast/apkparser"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// General Note: There are tools that can fully decompile an apk (e.g. jadx, apktool, etc.)
// However, none of these are in golang + they take awhile to run +
// they will decompile files that most likely don't contain secrets. So instead, we have a
// lightweight version that will search for secrets in the most common files that contain them.
// And run in a fraction of the time (ex: 15 seconds vs. 5 minutes)

// ToDo: Scan nested APKs (aka XAPK files). ATM the archive.go file will skip over them.
// ToDo: Provide file location information to secret output.

var (
	targetInstructionTypes = []string{"const-string", "iput-object"}
	// Note: We're only looking at `const-string` and `iput-objects` for now. This might need to be expanded.
	// If expanding, update precompiled REGEX below + update the formatInstruction function.
	// - const-string: loads a string into a register (value)
	// - iput-object: stores a string into a field (key)
	reFieldPrefix = regexp.MustCompile(`iput-object obj=\d+ field=com/[a-zA-Z0-9/_]+:`)
	reTypeSuffix  = regexp.MustCompile(`Ljava/lang/String; src=\d+`)
	reConstString = regexp.MustCompile(`const-string dst=\d+`)
	// Precompiling regexes for performance
)

// apkHandler handles apk archive formats.
type apkHandler struct{ *defaultHandler }

// newapkHandler creates an apkHandler.
func newAPKHandler() *apkHandler {
	return &apkHandler{defaultHandler: newDefaultHandler(apkHandlerType)}
}

// HandleFile processes apk formatted files.
func (h *apkHandler) HandleFile(ctx logContext.Context, input fileReader) (chan []byte, error) {
	apkChan := make(chan []byte, defaultBufferSize)

	go func() {
		ctx, cancel := logContext.WithTimeout(ctx, maxTimeout)
		defer cancel()
		defer close(apkChan)

		// Update the metrics for the file processing.
		start := time.Now()
		var err error
		defer func() {
			h.measureLatencyAndHandleErrors(start, err)
			h.metrics.incFilesProcessed()
		}()

		// Defer a panic recovery to handle any panics that occur during the APK processing.
		defer func() {
			if r := recover(); r != nil {
				// Return the panic as an error.
				if e, ok := r.(error); ok {
					err = e
				} else {
					err = fmt.Errorf("panic occurred: %v", r)
				}
				ctx.Logger().Error(err, "Panic occurred when reading apk archive")
			}
		}()

		if err = h.processAPK(ctx, input, apkChan); err != nil {
			ctx.Logger().Error(err, "error handling apk.")
		}
	}()
	return apkChan, nil
}

// processAPK processes the apk file and sends the extracted data to the provided channel.
func (h *apkHandler) processAPK(ctx logContext.Context, input fileReader, apkChan chan []byte) error {

	// Create a ZIP reader from the input fileReader
	zipReader, err := createZipReader(input)
	if err != nil {
		return err
	}

	// Extract the resources.arsc file into a ResourceTable (needed for XML decoding)
	resTable, err := parseResTable(zipReader)
	if err != nil {
		return err
	}

	// Process the ResourceTable file for secrets
	if err := h.processResources(ctx, resTable, apkChan); err != nil {
		ctx.Logger().Error(err, "failed to process resources.arsc")
	}

	// Process all files for secrets
	for _, file := range zipReader.File {
		if err := h.processFile(ctx, file, resTable, apkChan); err != nil {
			ctx.Logger().V(2).Info(fmt.Sprintf("failed to process file: %s", file.Name), "error", err)
		}
	}
	return nil
}

// processResources processes the resources.arsc file and sends the extracted data to the provided channel.
func (h *apkHandler) processResources(ctx logContext.Context, resTable *apkparser.ResourceTable, apkChan chan []byte) error {
	if resTable == nil {
		return errors.New("ResourceTable is nil")
	}
	rscStrRdr, err := extractStringsFromResTable(resTable)
	if err != nil {
		return fmt.Errorf("failed to parse strings from resources.arsc: %w", err)
	}
	return h.handleAPKFileContent(ctx, rscStrRdr, "resources.arsc", apkChan)
}

// processFile processes the file and sends the extracted data to the provided channel.
func (h *apkHandler) processFile(ctx logContext.Context, file *zip.File, resTable *apkparser.ResourceTable, apkChan chan []byte) error {
	// check if the file is empty
	if file.UncompressedSize64 == 0 {
		return nil
	}

	// Read the file data
	rdr, err := readFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", file.Name, err)
	}
	defer rdr.Close()

	// Decode the file based on its extension
	switch {
	case strings.HasSuffix(file.Name, ".xml"):
		xmlRdr, err := decodeXML(rdr, resTable)
		if err != nil {
			return fmt.Errorf("failed to decode xml file %s: %w", file.Name, err)
		}
		return h.handleAPKFileContent(ctx, xmlRdr, file.Name, apkChan)
	case strings.HasSuffix(file.Name, ".dex"):
		dexRdr, err := processDexFile(ctx, rdr)
		if err != nil {
			return fmt.Errorf("failed to decode dex file %s: %w", file.Name, err)
		}
		return h.handleAPKFileContent(ctx, dexRdr, file.Name, apkChan)
	default:
		return h.handleAPKFileContent(ctx, rdr, file.Name, apkChan)
	}
}

// handleAPKFileContent sends the extracted data to the provided channel via the handleNonArchiveContent function.
func (h *apkHandler) handleAPKFileContent(ctx logContext.Context, rdr io.Reader, fileName string, apkChan chan []byte) error {
	mimeReader, err := newMimeTypeReader(rdr)
	if err != nil {
		return fmt.Errorf("failed to create mimeTypeReader for file %s: %w", fileName, err)
	}
	ctx = logContext.WithValues(
		ctx,
		"filename", fileName,
	)
	return h.handleNonArchiveContent(ctx, mimeReader, apkChan)
}

// createZipReader creates a new ZIP reader from the input fileReader.
func createZipReader(input fileReader) (*zip.Reader, error) {
	size, err := input.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	// Reset the reader position to the start
	_, err = input.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}
	// Create a new ZIP reader for the data
	zipReader, err := zip.NewReader(input, size)
	if err != nil {
		return nil, err
	}
	return zipReader, err
}

// parseResTable parses the resources.arsc file and returns the ResourceTable.
func parseResTable(zipReader *zip.Reader) (*apkparser.ResourceTable, error) {
	for _, file := range zipReader.File {
		if file.Name == "resources.arsc" {
			rdr, err := readFile(file)
			if err != nil {
				return nil, err
			}
			defer rdr.Close()

			resTable, err := apkparser.ParseResourceTable(rdr)
			if err != nil {
				return nil, err
			}
			return resTable, nil
		}
	}
	return nil, errors.New("resources.arsc file not found in the APK archive")
}

// readFile reads the file from the zip archive and returns the data as an io.ReadCloser
// Note: responsibility of calling function to close the reader
func readFile(file *zip.File) (io.ReadCloser, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// hasSubstring checks if the string contains any of the provided substrings.
func hasSubstring(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// extractStringsFromResTable extracts the strings from the resources table
// Note: This is a hacky way to get the strings from the resources table
// APK strings are typically (always?) stored in the 0x7f000000-0x7fffffff range
// https://chromium.googlesource.com/chromium/src/+/master/build/android/docs/life_of_a_resource.md
func extractStringsFromResTable(resTable *apkparser.ResourceTable) (io.Reader, error) {
	var resourceStrings bytes.Buffer
	inStrings := false
	for i := 0x7f000000; i <= 0x7fffffff; i++ {
		entry, _ := resTable.GetResourceEntry(uint32(i))
		if entry == nil {
			continue
		}
		if entry.ResourceType == "string" {
			inStrings = true
			val, err := entry.GetValue().String()
			if err != nil {
				return nil, err
			}
			// Write directly to the buffer
			_, err = resourceStrings.WriteString(fmt.Sprintf("%s: %s\n", entry.Key, val))
			if err != nil {
				return nil, err
			}
		}
		// Exit the loop if we've finished processing the strings
		if inStrings && entry.ResourceType != "string" {
			break
		}
	}
	return &resourceStrings, nil
}

// processDexFile decodes the dex file and returns the relevant instructions
func processDexFile(ctx logContext.Context, rdr io.ReadCloser) (io.Reader, error) {
	// dextk.Read() requires an io.ReaderAt interface,
	// so we first convert the reader to a byte slice
	data, err := io.ReadAll(rdr)
	if err != nil {
		return nil, err
	}
	bytesRdr := bytes.NewReader(data)

	// Read the dex file
	dexReader, err := dextk.Read(bytesRdr)
	if err != nil {
		return nil, err
	}

	// Get relevant instruction data from the dex file
	var dexOutput bytes.Buffer
	ci := dexReader.ClassIter()
	for ci.HasNext() {
		node, err := ci.Next()
		if err != nil {
			break
		}
		processDexClass(ctx, dexReader, node, &dexOutput)
	}
	return &dexOutput, nil
}

// processDexClass processes a single class node's methods
func processDexClass(ctx logContext.Context, dexReader *dextk.Reader, node dextk.ClassNode, dexOutput *bytes.Buffer) {
	// Process Direct Methods
	processDexMethod(ctx, dexReader, node.DirectMethods, dexOutput)
	// Process Virtual Methods
	processDexMethod(ctx, dexReader, node.VirtualMethods, dexOutput)
}

// processDexMethod iterates over a slice of methods, processes each method,
// handles errors, and writes the output to dexOutput.
func processDexMethod(ctx logContext.Context, dexReader *dextk.Reader, methods []dextk.MethodNode, dexOutput *bytes.Buffer) {
	for _, method := range methods {
		out, err := parseDexInstructions(dexReader, method)
		if err != nil {
			ctx.Logger().V(2).Info("failed to process dex method", "error", err)
			continue // Continue processing other methods even if one fails
		}
		dexOutput.WriteString(out)
	}
}

// parseDexInstructions processes a dex method and returns the string representation of the instruction
func parseDexInstructions(r *dextk.Reader, m dextk.MethodNode) (string, error) {
	if m.CodeOff == 0 {
		return "", nil
	}

	c, err := r.ReadCodeAndParse(m.CodeOff)
	if err != nil {
		return "", err
	}

	var s strings.Builder
	for _, o := range c.Ops {
		if hasSubstring(o.String(), targetInstructionTypes) {
			s.WriteString(fmt.Sprintf("%s\n", formatInstruction(o.String())))
		}
	}
	return s.String(), nil
}

// formatInstruction removes unnecessary information from the dex instruction
// Note: This is critical for ensuring secret + keyword are in close proximity.
// If we expand the instructions we're looking at, this function will need to be updated.
func formatInstruction(line string) string {
	line = reFieldPrefix.ReplaceAllString(line, "")
	line = reTypeSuffix.ReplaceAllString(line, "")
	line = reConstString.ReplaceAllString(line, "")
	return line
}

func decodeXML(rdr io.ReadCloser, resTable *apkparser.ResourceTable) (io.Reader, error) {
	// Create a buffer to store the formatted XML data
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	// Parse the XML data using the apkparser library + resource table
	err := apkparser.ParseXml(rdr, enc, resTable)
	if err != nil {
		// If the error is due to plaintext XML, return the plaintext XML stringified
		if err.Error() == "xml is in plaintext, binary form expected" {
			xmlData, readErr := io.ReadAll(rdr)
			if readErr != nil {
				return nil, readErr
			}
			return bytes.NewReader(xmlData), nil
		}
		return nil, err
	}
	return &buf, nil
}
