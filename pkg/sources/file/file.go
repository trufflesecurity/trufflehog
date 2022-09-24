package file

import (
	"fmt"
	"os"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Source struct {
	sourceId, jobId, fileSize int64
	verify                    bool
	name, path                string
	file                      *os.File
	aCtx                      context.Context
	log                       *log.Entry
	sources.Progress
}

// Ensure the Source satisfies the interface at compile time.
var _ sources.Source = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_FILE
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized File source.
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, _ int) error {
	s.log = log.WithField("source", s.Type()).WithField("name", name)

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.File
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("failed to unmarshal connection: %w", err)
	}

	s.path = conn.Path
	// Set the path to stdin if one is not provided.
	if s.path == "" {
		s.path = os.Stdin.Name()
	}

	fi, err := os.Stat(s.path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	s.fileSize = fi.Size()

	return nil
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			s.log.WithError(err).Errorf("Failed to close file: %v.", s.path)
		}
	}(file)

	reReader, err := diskbufferreader.New(file)
	if err != nil {
		log.WithError(err).Error("Could not create re-readable reader.")
	}
	defer func(reReader *diskbufferreader.DiskBufferReader) {
		if err := reReader.Close(); err != nil {
			s.log.WithError(err).Error("Failed to close re-readable reader.")
		}
	}(reReader)

	chunkSkel := constructChunk(s)
	if handlers.HandleFile(reReader, chunkSkel, chunksChan) {
		return nil
	}

	if err := reReader.Reset(); err != nil {
		return err
	}
	reReader.Stop()

	for chunkData := range common.ChunkReader(reReader) {
		c := constructChunk(s)
		c.Data = chunkData

		select {
		case chunksChan <- c:
		case <-ctx.Done():
			s.log.WithError(ctx.Err()).Error("Context done.")
		}
	}
	return nil
}

func constructChunk(s *Source) *sources.Chunk {
	chunkSkel := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_File{
				File: &source_metadatapb.File{
					Path: sanitizer.UTF8(s.path),
				},
			},
		},
		Verify: s.verify,
	}
	return chunkSkel
}
