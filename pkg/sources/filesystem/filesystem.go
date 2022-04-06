package filesystem

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-errors/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	// These buffer sizes are mainly driven by our largest credential size, which is GCP @ ~2.25KB.
	// Having a peek size larger than that ensures that we have complete credential coverage in our chunks.
	BufferSize = 10 * 1024 // 10KB
	PeekSize   = 3 * 1024  // 3KB
)

type Source struct {
	name     string
	sourceId int64
	jobId    int64
	verify   bool
	paths    []string
	aCtx     context.Context
	log      *log.Entry
	sources.Progress
}

// Ensure the Source satisfies the interface at compile time
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized Filesystem source.
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = log.WithField("source", s.Type()).WithField("name", name)

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.Filesystem
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.paths = conn.Directories

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	for i, path := range s.paths {
		s.SetProgressComplete(i, len(s.paths), fmt.Sprintf("Path: %s", path), "")

		cleanPath := filepath.Clean(path)
		done := false
		go func() {
			<-ctx.Done()
			done = true
		}()

		err := fs.WalkDir(os.DirFS(cleanPath), ".", func(relativePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			path := filepath.Join(cleanPath, relativePath)

			fileStat, err := os.Stat(path)
			if err != nil {
				log.WithError(err).Warnf("unable to stat file: %s", path)
				return nil
			}
			if !fileStat.Mode().IsRegular() {
				return nil
			}

			inputFile, err := os.Open(path)
			if err != nil {
				log.Warn(err)
				return nil
			}
			defer inputFile.Close()

			reader := bufio.NewReaderSize(bufio.NewReader(inputFile), BufferSize)
			firstChunk := true
			for {
				if done {
					return nil
				}

				end := BufferSize
				buf := make([]byte, BufferSize)
				n, err := reader.Read(buf)

				if n < BufferSize {
					end = n
				}

				if end > 0 {
					data := buf[0:end]

					if firstChunk {
						firstChunk = false
						if common.SkipFile(path, data) {
							return nil
						}
					}

					// We are peeking in case a secret exists in our chunk boundaries,
					// but we never care if we've run into a peek error.
					peekData, _ := reader.Peek(PeekSize)
					chunksChan <- &sources.Chunk{
						SourceType: s.Type(),
						SourceName: s.name,
						SourceID:   s.SourceID(),
						Data:       append(data, peekData...),
						SourceMetadata: &source_metadatapb.MetaData{
							Data: &source_metadatapb.MetaData_Filesystem{
								Filesystem: &source_metadatapb.Filesystem{
									File: sanitizer.UTF8(path),
								},
							},
						},
						Verify: s.verify,
					}
				}

				// io.EOF can be emmitted when 0<n<buffer size
				if err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					} else {
						return err
					}
				}
			}
		})

		if err != nil && err != io.EOF {
			return errors.New(err)
		}

		if done {
			return nil
		}

	}
	return nil
}
