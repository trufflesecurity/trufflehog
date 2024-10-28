package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
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
	targetFileTypes = []string{".xml", ".dex", ".json"}
	// Note: Only targeting xml, dex, and json files for now. This might need to be expanded.
	// If expanding, ensure the processFile function is updated to handle the new file types.
	targetInstructionTypes = []string{"const-string", "iput-object"}
	// Note: We're only looking at `const-string` and `iput-objects` for now. This might need to be expanded.
	// If expanding, ensure the formatInstruction function is updated to handle the relevant instructions.
	// - const-string: loads a string into a register (value)
	// - iput-object: stores a string into a field (key)
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

	// Process all xml, json and dex files for secrets
	for _, file := range zipReader.File {
		if hasSuffix(file.Name, targetFileTypes) {
			if err := h.processFile(ctx, file, resTable, apkChan); err != nil {
				ctx.Logger().Error(err, fmt.Sprintf("failed to process file: %s", file.Name))
			}
		}
	}
	return nil
}

// processResources processes the resources.arsc file and sends the extracted data to the provided channel.
func (h *apkHandler) processResources(ctx logContext.Context, resTable *apkparser.ResourceTable, apkChan chan []byte) error {
	if resTable == nil {
		return errors.New("ResourceTable is nil")
	}
	resourcesStrings, err := extractStringsFromResTable(resTable)
	if err != nil {
		return fmt.Errorf("failed to parse strings from resources.arsc: %w", err)
	}
	h.handleAPKFileContent(ctx, resourcesStrings, "resources.arsc", apkChan)
	return nil
}

// processFile processes the file and sends the extracted data to the provided channel.
func (h *apkHandler) processFile(ctx logContext.Context, file *zip.File, resTable *apkparser.ResourceTable, apkChan chan []byte) error {
	data, err := readFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", file.Name, err)
	}
	if len(data) == 0 {
		return nil
	}

	// Decode the file based on its extension
	switch {
	case strings.HasSuffix(file.Name, ".xml"):
		xmlData, err := decodeXML(data, resTable)
		if err != nil {
			return fmt.Errorf("failed to decode xml file %s: %w", file.Name, err)
		}
		h.handleAPKFileContent(ctx, xmlData, file.Name, apkChan)
	case strings.HasSuffix(file.Name, ".dex"):
		dexStrings, err := decodeDexStrings(data)
		if err != nil {
			return fmt.Errorf("failed to decode dex file %s: %w", file.Name, err)
		}
		h.handleAPKFileContent(ctx, dexStrings, file.Name, apkChan)
	case strings.HasSuffix(file.Name, ".json"):
		h.handleAPKFileContent(ctx, string(data), file.Name, apkChan)
	}
	return nil
}

// handleAPKFileContent sends the extracted data to the provided channel via the handleNonArchiveContent function.
// Reviewers Note: If there's a better way to handle this, please let me know.
func (h *apkHandler) handleAPKFileContent(ctx logContext.Context, data string, fileName string, apkChan chan []byte) {
	r := mimeTypeReader{mimeExt: "", Reader: bytes.NewReader([]byte(data))}

	ctx = logContext.WithValues(
		ctx,
		"filename", fileName,
		"size", len(data),
	)

	if err := h.handleNonArchiveContent(ctx, r, apkChan); err != nil {
		ctx.Logger().Error(err, "error handling apk file")
	}
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
			data, err := readFile(file)
			if err != nil {
				return nil, err
			}
			resTable, err := apkparser.ParseResourceTable(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}
			return resTable, nil
		}
	}
	return nil, errors.New("resources.arsc file not found")
}

// readFile reads the file from the zip archive and returns the data as a byte slice.
func readFile(file *zip.File) ([]byte, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, rc)
	rc.Close() // Close immediately after reading
	if copyErr != nil {
		return nil, copyErr
	}
	return buf.Bytes(), nil
}

// hasSuffix checks if the name has any of the provided suffixes.
func hasSuffix(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
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
func extractStringsFromResTable(resTable *apkparser.ResourceTable) (string, error) {
	var resourceStrings string
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
				return "", err
			}
			resourceStrings += fmt.Sprintf("%s: %s\n", entry.Key, val)
		}
		// Exit the loop if we've finished processing the strings
		if inStrings && entry.ResourceType != "string" {
			break
		}
	}
	return resourceStrings, nil
}

// decodeDexStrings decodes the dex file and returns the string representation of the instructions
func decodeDexStrings(data []byte) (string, error) {
	// Read in dex file
	f := bytes.NewReader(data)
	r, err := dextk.Read(f)
	if err != nil {
		log.Panicln(err)
	}

	// Get strings from the dex file
	var dexOutput strings.Builder
	ci := r.ClassIter()
	for ci.HasNext() {
		node, err := ci.Next()
		if err != nil {
			break
		}

		for _, method := range node.DirectMethods {
			out, err := processDexMethod(r, method)
			if err != nil {
				return "", err
			}
			dexOutput.WriteString(out)
		}

		for _, method := range node.VirtualMethods {
			out, err := processDexMethod(r, method)
			if err != nil {
				return "", err
			}
			dexOutput.WriteString(out)
		}
	}
	return dexOutput.String(), nil
}

// processDexMethod processes a dex method and returns the string representation of the instruction
func processDexMethod(r *dextk.Reader, m dextk.MethodNode) (string, error) {
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
	reFieldPrefix := regexp.MustCompile(`iput-object obj=\d+ field=com/[a-zA-Z0-9/_]+:`)
	reTypeSuffix := regexp.MustCompile(`Ljava/lang/String; src=\d+`)
	reConstString := regexp.MustCompile(`const-string dst=\d+`)

	line = reFieldPrefix.ReplaceAllString(line, "")
	line = reTypeSuffix.ReplaceAllString(line, "")
	line = reConstString.ReplaceAllString(line, "")
	return line
}

func decodeXML(xmlData []byte, resTable *apkparser.ResourceTable) (string, error) {
	// Create a buffer to store the formatted XML data
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	// Parse the XML data using the apkparser library + resource table
	rdr := bytes.NewReader(xmlData)
	err := apkparser.ParseXml(rdr, enc, resTable)
	if err != nil {
		// If the error is due to plaintext XML, return the plaintext XML stringified
		if err.Error() == "xml is in plaintext, binary form expected" {
			return string(xmlData), nil
		}
		return "", err
	}
	return buf.String(), nil
}
