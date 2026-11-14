package json_enumerator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_JSON_ENUMERATOR

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	paths    []string
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType { return SourceType }
func (s *Source) SourceID() sources.SourceID { return s.sourceId }
func (s *Source) JobID() sources.JobID       { return s.jobId }

func (s *Source) Init(
	aCtx context.Context,
	name string,
	jobId sources.JobID,
	sourceId sources.SourceID,
	verify bool,
	connection *anypb.Any,
	concurrency int,
) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.JSONEnumerator
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.paths = conn.Paths

	aCtx.Logger().V(1).Info("JSON enumerator source initialized", "paths", len(s.paths))
	return nil
}

func (s *Source) Chunks(
	ctx context.Context,
	chunksChan chan *sources.Chunk,
	_ ...sources.ChunkingTarget,
) error {
	for i, path := range s.paths {
		if common.IsDone(ctx) {
			return nil
		}
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", path), "")
		if err := s.chunkJSONEnumerator(ctx, path, sources.ChanReporter{Ch: chunksChan}); err != nil {
			ctx.Logger().Error(err, "error scanning JSON enumerator", "path", path)
		}
	}

	return nil
}

// Enumerate implements the SourceUnitEnumerator interface, reporting each
// configured path as its own unit so paths can be chunked concurrently.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	var units, unreadable int
	for _, path := range s.paths {
		f, err := os.Open(path)
		if err != nil {
			unreadable++
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
		} else {
			_ = f.Close()
			units++
			if err := reporter.UnitOk(ctx, sources.CommonSourceUnit{ID: path}); err != nil {
				return err
			}
		}
	}
	ctx.Logger().V(1).Info("Enumerated paths", "units", units, "unreadable", unreadable)
	return nil
}

// ChunkUnit implements the SourceUnitChunker interface.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	path, _ := unit.SourceUnitID()
	if err := s.chunkJSONEnumerator(ctx, path, reporter); err != nil {
		return reporter.ChunkErr(ctx, err)
	}
	return nil
}

type jsonEntry struct {
	Metadata json.RawMessage
	Data     []byte
}

// jsonEntryAux is a helper struct to support marshalling the content to scan as either
// a UTF-8 string in `data` or a base64-encoded bytestring in `data_b64`.
type jsonEntryAux struct {
	Metadata *json.RawMessage `json:"metadata"`
	Data     *string          `json:"data,omitempty"`
	DataB64  *[]byte          `json:"data_b64,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for jsonEntry.
// If Data is valid UTF-8, it's serialized as a `data` string field.
// If Data is not valid UTF-8, it's serialized as a `data_b64` base64-encoded string field.
func (e *jsonEntry) MarshalJSON() ([]byte, error) {
	if utf8.Valid(e.Data) {
		s := string(e.Data)
		return json.Marshal(jsonEntryAux{
			Metadata: &e.Metadata,
			Data:     &s,
		})
	} else {
		return json.Marshal(jsonEntryAux{
			Metadata: &e.Metadata,
			DataB64:  &e.Data,
		})
	}
}

// UnmarshalJSON implements custom JSON unmarshaling for jsonEntry.
func (e *jsonEntry) UnmarshalJSON(data []byte) error {
	var aux jsonEntryAux
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Metadata == nil {
		return fmt.Errorf("missing metadata")
	}
	if aux.Data == nil && aux.DataB64 == nil {
		return fmt.Errorf("both data and data_b64 missing")
	}
	if aux.Data != nil && aux.DataB64 != nil {
		return fmt.Errorf("both data and data_b64 present")
	}

	e.Metadata = *aux.Metadata
	if aux.DataB64 != nil {
		e.Data = *aux.DataB64
	} else {
		e.Data = []byte(*aux.Data)
	}

	return nil
}

// chunkJSONEnumeratorReader scans every entry in input and returns how many entries it
// decoded. A bad entry stops the scan, since the decoder can't find where the next one
// starts.
func (s *Source) chunkJSONEnumeratorReader(
	ctx context.Context,
	input io.Reader,
	reporter sources.ChunkReporter,
) (int, error) {
	decoder := json.NewDecoder(input)
	var entry jsonEntry

	for i := 0; ; i++ {
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				// enumerator file is done
				return i, nil
			}
			return i, fmt.Errorf("decoding entry %d: %w", i, err)
		}
		// Never log the metadata or the data, they are user content.
		ctx.Logger().V(3).Info("Scanning entry", "entry", i, "data_bytes", len(entry.Data))

		metadataJSON, err := entry.Metadata.MarshalJSON()
		if err != nil {
			ctx.Logger().Error(err, "failed to convert metadata to JSON", "entry", i)
			continue
		}

		chunkSkel := &sources.Chunk{
			SourceType:   s.Type(),
			SourceName:   s.name,
			SourceID:     s.SourceID(),
			JobID:        s.JobID(),
			SourceVerify: s.verify,
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_JsonEnumerator{
					JsonEnumerator: &source_metadatapb.JSONEnumerator{
						Metadata: string(metadataJSON),
					},
				},
			},
		}

		err = handlers.HandleFile(ctx, bytes.NewReader(entry.Data), chunkSkel, reporter)
		if err != nil {
			ctx.Logger().Error(err, "failed to scan data", "entry", i)
			continue
		}
	}
}

func (s *Source) chunkJSONEnumerator(
	ctx context.Context,
	path string,
	reporter sources.ChunkReporter,
) error {
	zstdFile := strings.HasSuffix(path, ".zst") || strings.HasSuffix(path, ".zstd")
	ctx.Logger().V(2).Info("Scanning file", "path", path, "zstd", zstdFile)
	start := time.Now()

	enumeratorFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer func() { _ = enumeratorFile.Close() }()

	var input io.Reader = enumeratorFile
	if zstdFile {
		r, err := zstd.NewReader(enumeratorFile)
		if err != nil {
			return fmt.Errorf("unable to open zstd reader: %w", err)
		}
		defer r.Close()
		input = r
	}
	entries, err := s.chunkJSONEnumeratorReader(ctx, input, reporter)
	ctx.Logger().V(2).Info("Finished scanning file", "path", path, "entries", entries, "duration", time.Since(start))
	return err
}
