package json_enumerator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
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
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	concurrency int
	verify      bool
	paths       []string
	log         logr.Logger
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// var _ sources.SourceUnitEnumChunker = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType { return SourceType }
func (s *Source) SourceID() sources.SourceID { return s.sourceId }
func (s *Source) JobID() sources.JobID       { return s.jobId }

func (s *Source) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = aCtx.Logger()
	s.concurrency = concurrency

	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.JSONEnumerator
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}
	s.paths = conn.Paths

	return nil
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	for i, path := range s.paths {
		if common.IsDone(ctx) {
			return nil
		}
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", path), "")
		if err := s.chunkJSONEnumerator(ctx, path, chunksChan); err != nil {
			ctx.Logger().Error(err, "error scanning JSON enumerator", "path", path)
		}
	}

	return nil
}

type jsonEntry struct {
	Provenance json.RawMessage `json:"provenance"`
	Content    []byte          `json:"-"`
}

// jsonEntryAux is a helper struct to support marshalling the content to scan as either a UTF-8 string in `content` or a base64-encoded bytestring in `content_base64`.
type jsonEntryAux struct {
	Provenance *json.RawMessage `json:"provenance"`
	Content    *string          `json:"content,omitempty"`
	ContentB64 *[]byte          `json:"content_base64,omitempty"`
}

// MarshalJSON implements custom JSON marshaling for envelope.
// If Content is valid UTF-8, it's serialized as "content" (string).
// If Content is not valid UTF-8, it's base64-encoded and serialized as "content_b64".
func (e *jsonEntry) MarshalJSON() ([]byte, error) {
	if utf8.Valid(e.Content) {
		s := string(e.Content)
		return json.Marshal(jsonEntryAux{
			Provenance: &e.Provenance,
			Content:    &s,
		})
	} else {
		return json.Marshal(jsonEntryAux{
			Provenance: &e.Provenance,
			ContentB64: &e.Content,
		})
	}
}

// UnmarshalJSON implements custom JSON unmarshaling for envelope.
// It handles both "content" (string) and "content_b64" (base64-encoded string) fields.
func (e *jsonEntry) UnmarshalJSON(data []byte) error {
	var aux jsonEntryAux

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Provenance == nil {
		return fmt.Errorf("missing provenance")
	}
	if aux.Content == nil && aux.ContentB64 == nil {
		return fmt.Errorf("missing content / content_base64")
	}

	e.Provenance = *aux.Provenance
	if aux.ContentB64 != nil {
		e.Content = *aux.ContentB64
	} else {
		e.Content = []byte(*aux.Content)
	}

	return nil
}

func (s *Source) chunkJSONEnumerator(ctx context.Context, path string, chunksChan chan *sources.Chunk) error {
	ctx.Logger().V(3).Info("chunking JSON enumerator", "path", path)

	enumeratorFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer enumeratorFile.Close()

	decoder := json.NewDecoder(enumeratorFile)
	var entry jsonEntry
	var entryNum int64 = 0

	reporter := sources.ChanReporter{Ch: chunksChan}

	for {
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		sourceJSON, err := entry.Provenance.MarshalJSON()
		if err != nil {
			ctx.Logger().V(2).Error(err, "failed to convert provenance to JSON")
			continue
		}

		chunkSkel := &sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			Verify:     s.verify,
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_JsonEnumerator{
					JsonEnumerator: &source_metadatapb.JSONEnumerator{
						Provenance: string(sourceJSON),
					},
				},
			},
		}

		if err := handlers.HandleFile(ctx, bytes.NewReader(entry.Content), chunkSkel, reporter); err != nil {
			ctx.Logger().V(2).Error(err, "failed to scan content")
			continue
		}

		entryNum++
	}
}

/*
// Enumerate implements SourceUnitEnumerator interface.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	for _, path := range s.paths {
		if _, err := os.Lstat(filepath.Clean(path)); err != nil {
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
		} else {
			if err := reporter.UnitOk(ctx, sources.CommonSourceUnit{ID: path}); err != nil {
				return err
			}
		}
	}
	return nil
}

// ChunkUnit implements SourceUnitChunker interface.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	// TODO
	return nil
}
*/
