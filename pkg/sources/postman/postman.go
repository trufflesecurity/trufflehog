package postman

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_POSTMAN
)

type Source struct {
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	concurrency int
	log         logr.Logger
	sources.Progress
	jobPool *errgroup.Group
	client  *Client
	conn    *sourcespb.Postman
	sources.CommonSourceUnitUnmarshaller
}

//ToDo: Update this to match the proto file

type PMScanObject struct {
	Link            string
	WorkspaceUUID   string
	WorkspaceName   string
	GlobalID        string
	CollectionID    string
	CollectionName  string
	EnvironmentID   string
	EnvironmentName string
	RequestID       string
	RequestName     string
	FieldType       string
	FieldName       string
	VarType         string
	Data            string
}

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init returns an initialized Postman source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.Postman
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.conn = &conn

	switch conn.Credential.(type) {
	case *sourcespb.Postman_Token:
		if conn.GetToken() == "" {
			return errors.New("Postman token is empty")
		}
		s.client = NewClient(conn.GetToken())
		s.client.HTTPClient = common.RetryableHttpClientTimeout(3)

		// I think we should check access to the workspace

		//Consider adding an auth check here. But even if token is valid, doesn't mean we have access to the target source. So unnecssary?
	case *sourcespb.Postman_Unauthenticated:
		s.client = nil
		// No client needed if reading from local
	default:
		return errors.New("credential type not implemented for Travis CI")
	}

	return nil
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	defer close(chunksChan)
	// Prep all of the objects to scan. Then scan them.
	if s.conn.Workspace != "" {
		s.scanWorkspace(ctx, chunksChan)
	}

	if s.conn.Collection != "" {
		s.scanCollection(ctx, chunksChan)
		// Filter out collections

	}
	if s.conn.Environment != "" {
		s.scanEnvironment(ctx, chunksChan)
		// Filter out environments

	}

}

func (s *Source) scanWorkspace(ctx context.Context, chunksChan chan *sources.Chunk) {
	// Need to handle reading in a .zip file & checking validity of files inside.
	workspaceJSON, err := s.client.GetWorkspace(s.conn.Workspace)
	if err != nil {
		s.log.Error(err, "could not get workspace object", "workspace_uuid", s.conn.Workspace)
	}
	workspace, exists := workspaceJSON["workspace"].(map[string]interface{})
	if !exists {
		s.log.Error(err, "could not parse workspace object JSON", "workspace_uuid", s.conn.Workspace)
	}
	workspaceName, ok := workspace["name"].(string)
	if !ok {
		workspaceName = ""
	}

	workspaceUUID, ok := workspace["id"].(string)
	if !ok {
		workspaceUUID = ""
	}

	varSubMap := []map[string]interface{}{}
	extraKeywords := []string{workspaceName}
	s.scanGlobalVars(ctx, chunksChan, extraKeywords, &varSubMap)
	// Get all collections in workspace
	// Filter out collections
	//scanCollection(ctx, chunksChan)
	// Get all environments in workspace
	// Filter out enviroments
	// Get all globals in workspace
	// Scan workspace name
}

func (s *Source) scanGlobalVars(ctx context.Context, chunksChan chan *sources.Chunk, extraKeywords []string, varSubMap *[]map[string]interface{}) {
	globalVars, err := s.client.GetGlobals(s.conn.Workspace)
	if err != nil {
		s.log.Error(err, "could not get global variables object", "workspace_uuid", s.conn.Workspace)
	}
	pmObjToScan := []PMScanObject{}
	for _, globalVar := range globalVars.Data.Values {
		key := globalVar.Key
		value := globalVar.Value
		if value == nil {
			continue
		}
		variableType := globalVar.Type
		preScanObj := PMScanObject{
			Link:          "https://go.postman.com/globals/" + globalVars.Data.ID,
			WorkspaceUUID: s.Conn.Workspace,
			GlobalID:      globalVars.Data.ID,
			FieldType:     "Global Variable",
			FieldName:     key,
			VarType:       variableType,
			Data:          fmt.Sprintf("%s:%v\n", key, value),
		}
		pmObjToScan = append(pmObjToScan, preScanObj)
		for _, keyword := range extraKeywords {
			preScanObj.Data = fmt.Sprintf("%s:%v\n", keyword, value)
			pmObjToScan = append(pmObjToScan, preScanObj)
		}

		if globalVar.SessionValue != "" {
			preScanObj.Data = fmt.Sprintf("%s:%v\n", key, globalVar.SessionValue)
			pmObjToScan = append(pmObjToScan, preScanObj)
			for _, keyword := range extraKeywords {
				preScanObj.Data = fmt.Sprintf("%s:%v\n", keyword, globalVar.SessionValue)
				pmObjToScan = append(pmObjToScan, preScanObj)
			}
		}
	}
	for _, obj := range pmObjToScan {
		s.scanObject(ctx, chunksChan, obj)
	}
}

func (s *Source) scanCollection(ctx context.Context, chunksChan chan *sources.Chunk) {
	// Filter out collcetions
}

func (s *Source) scanEnvironment(ctx context.Context, chunksChan chan *sources.Chunk) {
	// Filter out environments
}

func (s *Source) collectionChunker(ctx context.Context, chunksChan chan *sources.Chunk, collections []string, errorCount *sync.Map, objectCount *uint64) {
	for _, collection := range collections {

		if common.IsDone(ctx) {
			return
		}

		if collection == nil {
			continue
		}

		s.jobPool.Go(func() error {
			defer common.RecoverWithExit(ctx)

			if strings.HasSuffix(*obj.Key, "/") {
				s.log.V(5).Info("Skipping directory", "object", *obj.Key)
				return nil
			}

			path := strings.Split(*obj.Key, "/")
			prefix := strings.Join(path[:len(path)-1], "/")

			nErr, ok := errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 3 {
				s.log.V(2).Info("Skipped due to excessive errors", "object", *obj.Key)
				return nil
			}

			// files break with spaces, must replace with +
			// objKey := strings.ReplaceAll(*obj.Key, " ", "+")
			ctx, cancel := context.WithTimeout(ctx, time.Second*5)
			defer cancel()
			res, err := client.GetObjectWithContext(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    obj.Key,
			})
			if err != nil {
				if !strings.Contains(err.Error(), "AccessDenied") {
					s.log.Error(err, "could not get S3 object", "object", *obj.Key)
				}

				nErr, ok := errorCount.Load(prefix)
				if !ok {
					nErr = 0
				}
				if nErr.(int) > 3 {
					s.log.V(3).Info("Skipped due to excessive errors", "object", *obj.Key)
					return nil
				}
				nErr = nErr.(int) + 1
				errorCount.Store(prefix, nErr)
				// too many consective errors on this page
				if nErr.(int) > 3 {
					s.log.V(2).Info("Too many consecutive errors, excluding prefix", "prefix", prefix)
				}
				return nil
			}

			bufferName := cleantemp.MkFilename()

			defer res.Body.Close()
			reader, err := diskbufferreader.New(res.Body, diskbufferreader.WithBufferName(bufferName))
			if err != nil {
				s.log.Error(err, "Could not create reader.")
				return nil
			}
			defer reader.Close()

			email := "Unknown"
			if obj.Owner != nil {
				email = *obj.Owner.DisplayName
			}
			modified := obj.LastModified.String()
			chunkSkel := &sources.Chunk{
				SourceType: s.Type(),
				SourceName: s.name,
				SourceID:   s.SourceID(),
				JobID:      s.JobID(),
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_S3{
						S3: &source_metadatapb.S3{
							Bucket:    bucket,
							File:      sanitizer.UTF8(*obj.Key),
							Link:      sanitizer.UTF8(makeS3Link(bucket, *client.Config.Region, *obj.Key)),
							Email:     sanitizer.UTF8(email),
							Timestamp: sanitizer.UTF8(modified),
						},
					},
				},
				Verify: s.verify,
			}
			if handlers.HandleFile(ctx, reader, chunkSkel, sources.ChanReporter{Ch: chunksChan}) {
				atomic.AddUint64(objectCount, 1)
				s.log.V(5).Info("S3 object scanned.", "object_count", objectCount, "page_number", pageNumber)
				return nil
			}

			if err := reader.Reset(); err != nil {
				s.log.Error(err, "Error resetting reader to start.")
			}
			reader.Stop()

			chunkReader := sources.NewChunkReader()
			chunkResChan := chunkReader(ctx, reader)
			for data := range chunkResChan {
				if err := data.Error(); err != nil {
					s.log.Error(err, "error reading chunk.")
					continue
				}
				chunk := *chunkSkel
				chunk.Data = data.Bytes()
				if err := common.CancellableWrite(ctx, chunksChan, &chunk); err != nil {
					return err
				}
			}

			atomic.AddUint64(objectCount, 1)
			s.log.V(5).Info("S3 object scanned.", "object_count", objectCount, "page_number", pageNumber)
			nErr, ok = errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 0 {
				errorCount.Store(prefix, 0)
			}

			return nil
		})
	}

	_ = s.jobPool.Wait()
}

// postmanChunker()

//maybe a process object function that takes a chunk and processes it?

// Need a function to get globals and process them, and then teh same for the rest
