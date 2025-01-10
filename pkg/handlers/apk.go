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
	"sync"
	"time"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/avast/apkparser"
	dextk "github.com/csnewman/dextk"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
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
	keywordMatcherOnce sync.Once
	keywordMatcher     *detectorKeywordMatcher
)

func defaultDetectorKeywords() []string {
	allDetectors := defaults.DefaultDetectors()

	// Remove keywords that cause lots of false positives.
	var exclusions = []string{
		"AKIA", "SG.", "pat", "token", "gh", "github", "sql", "database", "http", "key", "api-", "sdk-", "float", "-us", "gh", "pat", "token", "sid", "http", "private", "key", "segment", "close", "protocols", "verifier", "box", "privacy", "dm", "sl.", "vf", "flat",
	}

	var keywords []string
	exclusionSet := make(map[string]struct{})
	for _, excl := range exclusions {
		exclusionSet[strings.ToLower(excl)] = struct{}{}
	}

	// Aggregate all keywords from detectors.
	for _, detector := range allDetectors {
		for _, kw := range detector.Keywords() {
			kwLower := strings.ToLower(kw)
			if _, excluded := exclusionSet[kwLower]; !excluded {
				keywords = append(keywords, kwLower)
			}
		}
	}
	return keywords
}

// detectorKeywordMatcher encapsulates the Aho-Corasick trie for efficient keyword matching.
// It is used to scan APK file contents for keywords associated with our credential detectors.
// By only processing files/sections that contain these keywords, we can efficiently filter
// out irrelevant data and focus on content that is more likely to contain credentials.
// The Aho-Corasick algorithm provides fast, simultaneous matching of multiple patterns in
// a single pass through the text, which is crucial for performance when scanning large APK files.
type detectorKeywordMatcher struct{ trie *ahocorasick.Trie }

// getDefaultDetectorKeywordMatcher creates or returns the singleton detectorKeywordMatcher.
// This is implemented as a singleton for several important reasons:
// 1. Building the Aho-Corasick trie is computationally expensive and should only be done once.
// 2. The trie is immutable after construction and can be safely shared across goroutines.
// 3. The keyword list from the detectors is static for a given program execution.
// 4. Memory efficiency - we avoid duplicating the trie structure for each handler instance.
func getDefaultDetectorKeywordMatcher() *detectorKeywordMatcher {
	keywordMatcherOnce.Do(func() {
		keywords := defaultDetectorKeywords()
		keywordMatcher = &detectorKeywordMatcher{
			trie: ahocorasick.NewTrieBuilder().AddStrings(keywords).Build(),
		}
	})
	return keywordMatcher
}

// FindKeywords scans the input text and returns a slice of matched keywords.
// The method is thread-safe and uses a read lock since the trie is immutable.
// It returns unique matches only, eliminating duplicates that may occur when
// the same keyword appears multiple times in the input text.
func (km *detectorKeywordMatcher) FindKeywords(text []byte) []string {
	matches := km.trie.Match(bytes.ToLower(text))
	found := make([]string, 0, len(matches))
	seen := make(map[string]struct{}) // To avoid duplicate entries

	for _, match := range matches {
		keyword := match.MatchString()
		if _, exists := seen[keyword]; !exists {
			found = append(found, keyword)
			seen[keyword] = struct{}{}
		}
	}
	return found
}

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
type apkHandler struct {
	keywordMatcher *detectorKeywordMatcher
	*defaultHandler
}

// newAPKHandler creates an apkHandler.
func newAPKHandler() *apkHandler {
	return &apkHandler{
		defaultHandler: newDefaultHandler(apkHandlerType),
		keywordMatcher: getDefaultDetectorKeywordMatcher(),
	}
}

// HandleFile processes apk formatted files.
// Fatal errors that will stop processing:
// - Unable to create ZIP reader from input
// - Unable to parse resources.arsc file
// - Panics during processing (recovered but returned as errors)
//
// Non-fatal errors that will be logged and continue processing:
// - Failed to process individual files within the APK
// - Failed to process resources.arsc contents
// - Failed to process individual dex classes
// - Failed to decode specific XML files
func (h *apkHandler) HandleFile(ctx logContext.Context, input fileReader) chan DataOrErr {
	apkChan := make(chan DataOrErr, defaultBufferSize)

	go func() {
		defer close(apkChan)

		// Defer a panic recovery to handle any panics that occur during the APK processing.
		defer func() {
			if r := recover(); r != nil {
				// Return the panic as an error.
				var panicErr error
				if e, ok := r.(error); ok {
					panicErr = e
				} else {
					panicErr = fmt.Errorf("panic occurred: %v", r)
				}
				ctx.Logger().Error(panicErr, "Panic occurred when reading apk archive")
			}
		}()

		start := time.Now()
		err := h.processAPK(ctx, input, apkChan)
		if err == nil {
			h.metrics.incFilesProcessed()
		}

		h.measureLatencyAndHandleErrors(ctx, start, err, apkChan)
	}()

	return apkChan
}

// processAPK processes the apk file and sends the extracted data to the provided channel.
func (h *apkHandler) processAPK(ctx logContext.Context, input fileReader, apkChan chan DataOrErr) error {
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
func (h *apkHandler) processResources(ctx logContext.Context, resTable *apkparser.ResourceTable, apkChan chan DataOrErr) error {
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
func (h *apkHandler) processFile(
	ctx logContext.Context,
	file *zip.File,
	resTable *apkparser.ResourceTable,
	apkChan chan DataOrErr,
) error {
	// check if the file is empty
	if file.UncompressedSize64 == 0 {
		return nil
	}

	// Open the file from the zip archive
	f, err := openFile(file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", file.Name, err)
	}
	defer f.Close()

	rdr := iobuf.NewBufferedReaderSeeker(f)
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
		contentReader, err = h.processDexFile(ctx, rdr)
		if err != nil {
			return fmt.Errorf("failed to decode dex file %s: %w", file.Name, err)
		}
	default:
		contentReader = rdr
	}
	return h.handleAPKFileContent(ctx, contentReader, file.Name, apkChan)
}

// handleAPKFileContent sends the extracted data to the provided channel via the handleNonArchiveContent function.
func (h *apkHandler) handleAPKFileContent(
	ctx logContext.Context,
	rdr io.Reader,
	fileName string,
	apkChan chan DataOrErr,
) error {
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
func (h *apkHandler) processDexFile(ctx logContext.Context, rdr io.ReaderAt) (io.Reader, error) {
	dexReader, err := dextk.Read(rdr, dextk.WithReadCache(16))
	if err != nil {
		return nil, err
	}

	// Get relevant instruction data from the dex file
	var dexOutput bytes.Buffer
	ci := dexReader.ClassIter()
	for ci.HasNext() {
		node, err := ci.Next()
		if err != nil {
			ctx.Logger().Error(err, "failed to process a dex class")
			break
		}
		h.processDexClass(ctx, dexReader, node, &dexOutput)
	}

	return &dexOutput, nil
}

// processDexClass processes a single class node's methods
func (h *apkHandler) processDexClass(
	ctx logContext.Context,
	dexReader *dextk.Reader,
	node dextk.ClassNode,
	dexOutput *bytes.Buffer,
) {
	var classOutput bytes.Buffer
	methodValues := make(map[string]struct{})

	// Process Direct Methods
	processDexMethod(ctx, dexReader, node.DirectMethods, &classOutput, methodValues)
	// Process Virtual Methods
	processDexMethod(ctx, dexReader, node.VirtualMethods, &classOutput, methodValues)

	// Write the classOutput to the dexOutput
	dexOutput.Write(classOutput.Bytes())

	// Check if classOutput contains any of the default keywords
	foundKeywords := h.keywordMatcher.FindKeywords(classOutput.Bytes())

	// For each found keyword, create a keyword:value pair and append to dexOutput
	for str := range methodValues {
		for _, keyword := range foundKeywords {
			dexOutput.WriteString(keyword + ":" + str + "\n")
		}
	}
}

// processDexMethod iterates over a slice of methods, processes each method,
// handles errors, and writes the output to dexOutput.
func processDexMethod(
	ctx logContext.Context,
	dexReader *dextk.Reader,
	methods []dextk.MethodNode,
	classOutput *bytes.Buffer,
	methodValues map[string]struct{},
) {
	for _, method := range methods {
		s, err := parseDexInstructions(dexReader, method, methodValues)
		if err != nil {
			ctx.Logger().V(2).Info("failed to process dex method", "error", err)
			continue
		}
		classOutput.Write(s.Bytes())
	}
}

// parseDexInstructions processes a dex method and returns the string representation of the instruction
func parseDexInstructions(r *dextk.Reader, m dextk.MethodNode, methodValues map[string]struct{}) (*bytes.Buffer, error) {
	var instrBuf bytes.Buffer

	if m.CodeOff == 0 {
		return &instrBuf, nil
	}

	c, err := r.ReadCodeAndParse(m.CodeOff)
	if err != nil {
		return &instrBuf, err
	}

	// Iterate over the instructions and extract the relevant values
	for _, o := range c.Ops {
		oStr := o.String()

		instructionType := getInstructionType(oStr)
		if instructionType == "" {
			continue
		}

		val := formatAndFilterInstruction(oStr)
		if val != "" {
			instrBuf.WriteString(val + "\n")
			if instructionType == stringInstructionType {
				methodValues[val] = struct{}{}
			}
		}
	}
	return &instrBuf, nil
}

// getInstructionType checks for specific target instructions
func getInstructionType(instruction string) string {
	for _, t := range targetInstructionTypes {
		if strings.HasPrefix(instruction, t) {
			return t
		}
	}
	return ""
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

func decodeXML(rdr io.ReadSeeker, resTable *apkparser.ResourceTable) (io.Reader, error) {
	// Create a buffer to store the formatted XML data
	// Note: in the future, consider a custom writer that spills to disk if the buffer gets too large
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	// Parse the XML data using the apkparser library + resource table
	err := apkparser.ParseXml(rdr, enc, resTable)
	if err == nil {
		return &buf, nil
	}

	// If the error is due to plaintext XML, return the plaintext XML.
	if errors.Is(err, apkparser.ErrPlainTextManifest) {
		if _, err := rdr.Seek(0, io.SeekStart); err != nil {
			return rdr, fmt.Errorf("error resetting reader after XML parsing error: %w", err)
		}
		return rdr, nil
	}
	return nil, err
}
