package json_enumerator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

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
		if err := s.chunkJSONEnumerator(ctx, path, chunksChan); err != nil {
			ctx.Logger().Error(err, "error scanning JSON enumerator", "path", path)
		}
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

func (s *Source) chunkJSONEnumeratorReader(
	ctx context.Context,
	input io.Reader,
	chunksChan chan *sources.Chunk,
) error {
	decoder := json.NewDecoder(input)
	var entry jsonEntry

	reporter := sources.ChanReporter{Ch: chunksChan}

	for {
		if err := decoder.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				// enumerator file is done
				return nil
			}
			return err
		}

		metadataJSON, err := entry.Metadata.MarshalJSON()
		if err != nil {
			ctx.Logger().Error(err, "failed to convert metadata to JSON")
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
						Metadata: string(metadataJSON),
					},
				},
			},
		}

		err = handlers.HandleFile(ctx, bytes.NewReader(entry.Data), chunkSkel, reporter)
		if err != nil {
			ctx.Logger().Error(err, "failed to scan data")
			continue
		}
	}
}

func (s *Source) chunkJSONEnumerator(
	ctx context.Context,
	path string,
	chunksChan chan *sources.Chunk,
) error {
	ctx.Logger().V(3).Info("chunking JSON enumerator", "path", path)

	enumeratorFile, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}
	defer enumeratorFile.Close()

	return s.chunkJSONEnumeratorReader(ctx, enumeratorFile, chunksChan)
}
