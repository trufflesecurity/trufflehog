package s3

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
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
	name        string
	sourceId    int64
	jobId       int64
	verify      bool
	concurrency int
	log         logr.Logger
	sources.Progress
	errorCount *sync.Map
	conn       *sourcespb.S3
	jobPool    *errgroup.Group
}

// Ensure the Source satisfies the interface at compile time
var _ sources.Source = (*Source)(nil)

// Type returns the type of source
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_S3
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized AWS source
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = context.WithValues(aCtx, "source", s.Type(), "name", name).Logger()

	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.concurrency = concurrency
	s.errorCount = &sync.Map{}
	s.log = aCtx.Logger()
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.S3
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}
	s.conn = &conn

	return nil
}

func (s *Source) newClient(region string) (*s3.S3, error) {
	cfg := aws.NewConfig()
	cfg.CredentialsChainVerboseErrors = aws.Bool(true)
	cfg.Region = aws.String(region)

	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.S3_AccessKey:
		cfg.Credentials = credentials.NewStaticCredentials(cred.AccessKey.Key, cred.AccessKey.Secret, "")
	case *sourcespb.S3_Unauthenticated:
		cfg.Credentials = credentials.AnonymousCredentials
	case *sourcespb.S3_CloudEnvironment:
		// Nothing needs to be done!
	default:
		return nil, errors.Errorf("invalid configuration given for %s source", s.name)
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *cfg,
	})
	if err != nil {
		return nil, err
	}

	return s3.New(sess), nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	const defaultAWSRegion = "us-east-1"

	client, err := s.newClient(defaultAWSRegion)
	if err != nil {
		return errors.WrapPrefix(err, "could not create s3 client", 0)
	}

	var bucketsToScan []string

	switch s.conn.GetCredential().(type) {
	case *sourcespb.S3_AccessKey, *sourcespb.S3_CloudEnvironment:
		if len(s.conn.Buckets) == 0 {
			res, err := client.ListBuckets(&s3.ListBucketsInput{})
			if err != nil {
				return fmt.Errorf("could not list s3 buckets: %w", err)
			}
			buckets := res.Buckets
			for _, bucket := range buckets {
				bucketsToScan = append(bucketsToScan, *bucket.Name)
			}
		} else {
			bucketsToScan = s.conn.Buckets
		}
	case *sourcespb.S3_Unauthenticated:
		bucketsToScan = s.conn.Buckets
	default:
		return errors.Errorf("invalid configuration given for %s source", s.name)
	}

	objectCount := uint64(0)
	for i, bucket := range bucketsToScan {
		if common.IsDone(ctx) {
			return nil
		}

		s.SetProgressComplete(i, len(bucketsToScan), fmt.Sprintf("Bucket: %s", bucket), "")

		s.log.Info("Scanning bucket", "bucket", bucket)
		region, err := s3manager.GetBucketRegionWithClient(context.Background(), client, bucket)
		if err != nil {
			s.log.Error(err, "could not get s3 region for bucket", "bucket", bucket)
			continue
		}
		var regionalClient *s3.S3
		if region != defaultAWSRegion {
			regionalClient, err = s.newClient(region)
			if err != nil {
				s.log.Error(err, "could not make regional s3 client")
			}
		} else {
			regionalClient = client
		}

		errorCount := sync.Map{}

		err = regionalClient.ListObjectsV2PagesWithContext(
			ctx, &s3.ListObjectsV2Input{Bucket: &bucket},
			func(page *s3.ListObjectsV2Output, last bool) bool {
				s.pageChunker(ctx, regionalClient, chunksChan, bucket, page, &errorCount, i+1, &objectCount)
				return true
			})

		if err != nil {
			s.log.Error(err, "could not list objects in s3 bucket", "bucket", bucket)
		}
	}
	s.SetProgressComplete(len(bucketsToScan), len(bucketsToScan), fmt.Sprintf("Completed scanning source %s. %d objects scanned.", s.name, objectCount), "")

	return nil
}

// pageChunker emits chunks onto the given channel from a page
func (s *Source) pageChunker(ctx context.Context, client *s3.S3, chunksChan chan *sources.Chunk, bucket string, page *s3.ListObjectsV2Output, errorCount *sync.Map, pageNumber int, objectCount *uint64) {
	for _, obj := range page.Contents {
		obj := obj
		if common.IsDone(ctx) {
			return
		}

		if obj == nil {
			continue
		}

		// skip GLACIER and GLACIER_IR objects
		if obj.StorageClass == nil || strings.Contains(*obj.StorageClass, "GLACIER") {
			s.log.V(5).Info("Skipping object in storage class", "storage_class", *obj.StorageClass, "object", *obj.Key)
			continue
		}

		// ignore large files
		if *obj.Size > int64(250*common.MB) {
			s.log.V(3).Info("Skipping %d byte file (over 250MB limit)", "object", *obj.Key)
			return
		}

		// file empty file
		if *obj.Size == 0 {
			s.log.V(5).Info("Skipping 0 byte file", "object", *obj.Key)
			return
		}

		// skip incompatible extensions
		if common.SkipFile(*obj.Key) {
			s.log.V(5).Info("Skipping file with incompatible extension", "object", *obj.Key)
			return
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

			defer res.Body.Close()
			reader, err := diskbufferreader.New(res.Body)
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
			if handlers.HandleFile(ctx, reader, chunkSkel, chunksChan) {
				atomic.AddUint64(objectCount, 1)
				s.log.V(5).Info("S3 object scanned.", "object_count", objectCount, "page_number", pageNumber)
				return nil
			}

			if err := reader.Reset(); err != nil {
				s.log.Error(err, "Error resetting reader to start.")
			}
			reader.Stop()

			chunk := *chunkSkel
			chunkData, err := io.ReadAll(reader)
			if err != nil {
				s.log.Error(err, "Could not read file data.")
				return nil
			}
			atomic.AddUint64(objectCount, 1)
			s.log.V(5).Info("S3 object scanned.", "object_count", objectCount, "page_number", pageNumber)
			chunk.Data = chunkData
			chunksChan <- &chunk

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

// S3 links currently have the general format of:
// https://[bucket].s3[.region unless us-east-1].amazonaws.com/[key]
func makeS3Link(bucket, region, key string) string {
	if region == "us-east-1" {
		region = ""
	} else {
		region = "." + region
	}
	return fmt.Sprintf("https://%s.s3%s.amazonaws.com/%s", bucket, region, key)
}
