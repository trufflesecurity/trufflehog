package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	dextk "github.com/csnewman/dextk"

	"github.com/avast/apkparser"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/iobuf"
)

// General Note: There are tools that can fully decompile an apk (e.g. jadx, apktool, etc.)
// However, none of these are in golang + they take awhile to run +
// they will decompile files that most likely don't contain secrets. So instead, we have a
// lightweight version that will search for secrets in the most common files that contain them.
// And run in a fraction of the time (ex: 15 seconds vs. 5 minutes)

// ToDo: Scan nested APKs (aka XAPK files). ATM the archive.go file will skip over them.
// ToDo: Provide file location information to secret output.

var (
	stringInstructionType  = "const-string"
	targetInstructionTypes = []string{stringInstructionType, "iput-object", "sput-object", "const-class", "invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface"}
	// Note: We're only looking at a subset of instructions.
	// If expanding, update precompiled REGEX below.
	// - const-string: loads a string into a register (value)
	// - iput-object: stores a string into a field (key)
	// - the rest have to do with function, methods, objects and classes.
	reIPutRegex       = regexp.MustCompile(`iput-object obj=\d+ field=com/[a-zA-Z0-9/_]+:([a-zA-Z0-9_]+):`)
	reSPutRegex       = regexp.MustCompile(`sput-object field=com/[a-zA-Z0-9/_]+:([a-zA-Z0-9_]+):`)
	reConstRegex      = regexp.MustCompile(`const-string(?:/jumbo)? dst=\d+ value='([^']*)'`)
	reConstClassRegex = regexp.MustCompile(`const-class dst=\d+ value='[a-zA-Z0-9/_$]+/([a-zA-Z0-9]+)(?:\$|;)`)
	reInvokeRegex     = regexp.MustCompile(`invoke-(?:virtual|super|direct|static|interface)(?:/range)? method=[a-zA-Z0-9/._$]+/([a-zA-Z0-9_$]+:[a-zA-Z0-9_<]+)`)
	reInstructions    = []*regexp.Regexp{
		reIPutRegex,
		reSPutRegex,
		reConstRegex,
		reConstClassRegex,
		reInvokeRegex,
	}
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
			ctx.Logger().Error(err, "error processing apk content")
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

	// Open the file from the zip archive
	rdr, err := openFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", file.Name, err)
	}
	defer rdr.Close()

	var contentReader io.Reader
	// Decode the file based on its extension
	switch strings.ToLower(filepath.Ext(file.Name)) {
	case ".xml":
		contentReader, err = decodeXML(rdr, resTable)
		if err != nil {
			return fmt.Errorf("failed to decode xml file %s: %w", file.Name, err)
		}
	case ".dex":
		contentReader, err = processDexFile(ctx, rdr)
		if err != nil {
			return fmt.Errorf("failed to decode dex file %s: %w", file.Name, err)
		}
	default:
		contentReader = rdr
	}
	return h.handleAPKFileContent(ctx, contentReader, file.Name, apkChan)
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
	size, err := input.Size()
	if err != nil {
		return nil, err
	}
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
			rdr, err := openFile(file)
			if err != nil {
				return nil, err
			}

			resTable, err := apkparser.ParseResourceTable(rdr)
			rdr.Close()
			if err != nil {
				return nil, err
			}
			return resTable, nil
		}
	}
	return nil, errors.New("resources.arsc file not found in the APK archive")
}

// openFile opens the file from the zip archive and returns the data as an io.ReadCloser
// Note: responsibility of calling function to close the reader
func openFile(file *zip.File) (io.ReadCloser, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	return rc, nil
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
			resourceStrings.WriteString(entry.Key)
			resourceStrings.WriteString(": ")
			resourceStrings.WriteString(val)
			resourceStrings.WriteString("\n")
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
	// dextk.Read() requires an io.ReaderAt interface
	dexReader, err := dextk.Read(iobuf.NewBufferedReaderSeeker(rdr))
	if err != nil {
		return nil, err
	}

	defaultKeywords := DefaultDetectorKeywords()

	// Get relevant instruction data from the dex file
	var dexOutput bytes.Buffer
	ci := dexReader.ClassIter()
	for ci.HasNext() {
		node, err := ci.Next()
		if err != nil {
			break
		}
		processDexClass(ctx, dexReader, node, defaultKeywords, &dexOutput)
	}

	return &dexOutput, nil
}

// processDexClass processes a single class node's methods
func processDexClass(ctx logContext.Context, dexReader *dextk.Reader, node dextk.ClassNode, defaultKeywords map[string]struct{}, dexOutput *bytes.Buffer) {

	var classOutput bytes.Buffer
	methodValues := make(map[string]struct{})

	// Process Direct Methods
	processDexMethod(ctx, dexReader, node.DirectMethods, &classOutput, methodValues)
	// Process Virtual Methods
	processDexMethod(ctx, dexReader, node.VirtualMethods, &classOutput, methodValues)

	// Write the classOutput to the dexOutput
	dexOutput.Write(classOutput.Bytes())

	// Stringify the classOutput value for case-insensitive keyword matching
	classOutputLower := strings.ToLower(classOutput.String())

	// Check if classOutput contains any of the default keywords
	foundKeywords := make(map[string]struct{})
	for keyword := range defaultKeywords {
		if strings.Contains(classOutputLower, keyword) {
			foundKeywords[keyword] = struct{}{} // Directly add to the map
		}
	}

	// For each found keyword, create a keyword:value pair and append to dexOutput
	var keyValuePairs bytes.Buffer
	for str := range methodValues {
		for keyword := range foundKeywords {
			keyValuePairs.Reset()
			keyValuePairs.WriteString(keyword + ":" + str + "\n")
			dexOutput.Write(keyValuePairs.Bytes())
		}
	}
}

// processDexMethod iterates over a slice of methods, processes each method,
// handles errors, and writes the output to dexOutput.
func processDexMethod(ctx logContext.Context, dexReader *dextk.Reader, methods []dextk.MethodNode, classOutput *bytes.Buffer, methodValues map[string]struct{}) {
	for _, method := range methods {
		s, values, err := parseDexInstructions(dexReader, method)
		if err != nil {
			ctx.Logger().V(2).Info("failed to process dex method", "error", err)
			continue
		}
		classOutput.Write(s.Bytes())
		for val := range values {
			methodValues[val] = struct{}{}
		}
	}
}

// parseDexInstructions processes a dex method and returns the string representation of the instruction
func parseDexInstructions(r *dextk.Reader, m dextk.MethodNode) (*bytes.Buffer, map[string]struct{}, error) {
	var s bytes.Buffer
	values := make(map[string]struct{})

	if m.CodeOff == 0 {
		return &s, values, nil
	}

	c, err := r.ReadCodeAndParse(m.CodeOff)
	if err != nil {
		return &s, values, err
	}

	// Iterate over the instructions and extract the relevant values
	for _, o := range c.Ops {
		oStr := o.String()
		// Filter out instructions that are not in our targetInstructionTypes
		parsedVal := formatAndFilterInstruction(oStr)
		if parsedVal == "" {
			continue
		}
		// If instruction is a const-string, then store as in values map
		// this is used when creating keyword:value pairs in processDexClass()
		if strings.HasPrefix(oStr, stringInstructionType) {
			values[parsedVal] = struct{}{}
		}
		// Write the parsedVal to the buffer
		s.WriteString(parsedVal)
	}
	return &s, values, nil
}

// formatAndFilterInstruction looks for a match to our regex and returns it
// Note: This is critical for ensuring secret + keyword are in close proximity.
// If we expand the instructions we're looking at, this function will need to be updated.
func formatAndFilterInstruction(line string) string {
	for _, re := range reInstructions {
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

func decodeXML(rdr io.ReadCloser, resTable *apkparser.ResourceTable) (io.Reader, error) {
	//Convert rdr to BufferedReadSeeker to support rewinding
	bufRdr := iobuf.NewBufferedReaderSeeker(rdr)

	// Create a buffer to store the formatted XML data
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	// Parse the XML data using the apkparser library + resource table
	err := apkparser.ParseXml(bufRdr, enc, resTable)
	if err != nil {
		// If the error is due to plaintext XML, return the plaintext XML
		if errors.Is(err, apkparser.ErrPlainTextManifest) {
			if _, err := bufRdr.Seek(0, io.SeekStart); err != nil {
				return bufRdr, fmt.Errorf("error resetting reader after XML parsing error: %w", err)
			}
			return bufRdr, nil
		}
		return nil, err
	}
	return &buf, nil
}
