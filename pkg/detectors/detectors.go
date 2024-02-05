package detectors

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/url"
	"strings"
	"unicode"

	"errors"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Detector defines an interface for scanning for and verifying secrets.
type Detector interface {
	// FromData will scan bytes for results, and optionally verify them.
	FromData(ctx context.Context, verify bool, data []byte) ([]Result, error)
	// Keywords are used for efficiently pre-filtering chunks using substring operations.
	// Use unique identifiers that are part of the secret if you can, or the provider name.
	Keywords() []string
	// Type returns the DetectorType number from detectors.proto for the given detector.
	Type() detectorspb.DetectorType
}

// Versioner is an optional interface that a detector can implement to
// differentiate instances of the same detector type.
type Versioner interface {
	Version() int
}

// EndpointCustomizer is an optional interface that a detector can implement to
// support verifying against user-supplied endpoints.
type EndpointCustomizer interface {
	SetEndpoints(...string) error
	DefaultEndpoint() string
}

type Result struct {
	// DetectorType is the type of Detector.
	DetectorType detectorspb.DetectorType
	// DetectorName is the name of the Detector. Used for custom detectors.
	DetectorName string
	// DecoderType is the type of Decoder.
	DecoderType detectorspb.DecoderType
	Verified    bool
	// Raw contains the raw secret identifier data. Prefer IDs over secrets since it is used for deduping after hashing.
	Raw []byte
	// RawV2 contains the raw secret identifier that is a combination of both the ID and the secret.
	// This is used for secrets that are multi part and could have the same ID. Ex: AWS credentials
	RawV2 []byte
	// Redacted contains the redacted version of the raw secret identification data for display purposes.
	// A secret ID should be used if available.
	Redacted       string
	ExtraData      map[string]string
	StructuredData *detectorspb.StructuredData

	// This field should only be populated if the verification process itself failed in a way that provides no
	// information about the verification status of the candidate secret, such as if the verification request timed out.
	verificationError error
}

// SetVerificationError is the only way to set a verification error. Any sensetive values should be passed-in as secrets to be redacted.
func (r *Result) SetVerificationError(err error, secrets ...string) {
	if err != nil {
		r.verificationError = redactSecrets(err, secrets...)
	}
}

// Public accessors for the fields could also be provided if needed.
func (r *Result) VerificationError() error {
	return r.verificationError
}

// redactSecrets replaces all instances of the given secrets with [REDACTED] in the error message.
func redactSecrets(err error, secrets ...string) error {
	lastErr := unwrapToLast(err)
	errStr := lastErr.Error()
	for _, secret := range secrets {
		errStr = strings.Replace(errStr, secret, "[REDACTED]", -1)
	}
	return errors.New(errStr)
}

// unwrapToLast returns the last error in the chain of errors.
// This is added to exclude non-essential details (like URLs) for brevity and security.
// Also helps us optimize performance in redaction and enhance log clarity.
func unwrapToLast(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			// We've reached the last error in the chain
			return err
		}
		err = unwrapped
	}
}

type ResultWithMetadata struct {
	// SourceMetadata contains source-specific contextual information.
	SourceMetadata *source_metadatapb.MetaData
	// SourceID is the ID of the source that the API uses to map secrets to specific sources.
	SourceID sources.SourceID
	// SourceType is the type of Source.
	SourceType sourcespb.SourceType
	// SourceName is the name of the Source.
	SourceName string
	Result
	// Data from the sources.Chunk which this result was emitted for
	Data []byte
}

// CopyMetadata returns a detector result with included metadata from the source chunk.
func CopyMetadata(chunk *sources.Chunk, result Result) ResultWithMetadata {
	return ResultWithMetadata{
		SourceMetadata: chunk.SourceMetadata,
		SourceID:       chunk.SourceID,
		SourceType:     chunk.SourceType,
		SourceName:     chunk.SourceName,
		Result:         result,
		Data:           chunk.Data,
	}
}

// CleanResults returns all verified secrets, and if there are no verified secrets,
// just one unverified secret if there are any.
func CleanResults(results []Result) []Result {
	if len(results) == 0 {
		return results
	}

	var cleaned = make(map[string]Result, 0)

	for _, s := range results {
		if s.Verified {
			cleaned[s.Redacted] = s
		}
	}

	if len(cleaned) == 0 {
		return results[:1]
	}

	results = results[:0]
	for _, r := range cleaned {
		results = append(results, r)
	}

	return results
}

// PrefixRegex ensures that at least one of the given keywords is within
// 20 characters of the capturing group that follows.
// This can help prevent false positives.
func PrefixRegex(keywords []string) string {
	pre := `(?i)(?:`
	middle := strings.Join(keywords, "|")
	post := `)(?:.|[\n\r]){0,40}`
	return pre + middle + post
}

// KeyIsRandom is a Low cost check to make sure that 'keys' include a number to reduce FPs.
// Golang doesn't support regex lookaheads, so must be done in separate calls.
// TODO improve checks. Shannon entropy did not work well.
func KeyIsRandom(key string) bool {
	for _, ch := range key {
		if unicode.IsDigit(ch) {
			return true
		}
	}

	return false
}

func MustGetBenchmarkData() map[string][]byte {
	sizes := map[string]int{
		"xsmall":  10,          // 10 bytes
		"small":   100,         // 100 bytes
		"medium":  1024,        // 1KB
		"large":   10 * 1024,   // 10KB
		"xlarge":  100 * 1024,  // 100KB
		"xxlarge": 1024 * 1024, // 1MB
	}
	data := make(map[string][]byte)

	for key, size := range sizes {
		// Generating a byte slice of a specific size with random data.
		content := make([]byte, size)
		for i := 0; i < size; i++ {
			randomByte, err := rand.Int(rand.Reader, big.NewInt(256))
			if err != nil {
				panic(err)
			}
			content[i] = byte(randomByte.Int64())
		}
		data[key] = content
	}

	return data
}

func RedactURL(u url.URL) string {
	u.User = url.UserPassword(u.User.Username(), "********")
	return strings.TrimSpace(strings.Replace(u.String(), "%2A", "*", -1))
}
