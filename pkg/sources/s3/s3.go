package s3

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/go-errors/errors"
	log "github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type Source struct {
	name        string
	sourceId    int64
	jobId       int64
	verify      bool
	concurrency int
	aCtx        context.Context
	log         *log.Entry
	sources.Progress
	errorCount *sync.Map
	conn       *sourcespb.S3
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
	s.log = log.WithField("source", s.Type()).WithField("name", name)

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.concurrency = concurrency
	s.errorCount = &sync.Map{}

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
	client, err := s.newClient("us-east-1")
	if err != nil {
		return errors.WrapPrefix(err, "could not create s3 client", 0)
	}

	bucketsToScan := []string{}

	switch s.conn.GetCredential().(type) {
	case *sourcespb.S3_AccessKey, *sourcespb.S3_CloudEnvironment:
		if len(s.conn.Buckets) == 0 {
			res, err := client.ListBuckets(&s3.ListBucketsInput{})
			if err != nil {
				s.log.Errorf("could not list s3 buckets: %s", err)
				return errors.WrapPrefix(err, "could not list s3 buckets", 0)
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

	for i, bucket := range bucketsToScan {
		if common.IsDone(ctx) {
			return nil
		}

		s.SetProgressComplete(i, len(bucketsToScan), fmt.Sprintf("Bucket: %s", bucket), "")

		s.log.Debugf("Scanning bucket: %s", bucket)
		region, err := s3manager.GetBucketRegionWithClient(context.Background(), client, bucket)
		if err != nil {
			s.log.WithError(err).Errorf("could not get s3 region for bucket: %s", bucket)
			continue
		}
		var regionalClient *s3.S3
		if region != "us-east-1" {
			regionalClient, err = s.newClient(region)
			if err != nil {
				s.log.WithError(err).Error("could not make regional s3 client")
			}
		} else {
			regionalClient = client
		}
		//Forced prefix for testing
		//pf := "public"
		errorCount := sync.Map{}

		err = regionalClient.ListObjectsV2PagesWithContext(
			ctx, &s3.ListObjectsV2Input{Bucket: &bucket},
			func(page *s3.ListObjectsV2Output, last bool) bool {
				s.pageChunker(ctx, regionalClient, chunksChan, bucket, page, &errorCount)
				return true
			})

		if err != nil {
			s.log.WithError(err).Errorf("could not list objects in s3 bucket: %s", bucket)
			return errors.WrapPrefix(err, fmt.Sprintf("could not list objects in s3 bucket: %s", bucket), 0)
		}

	}

	return nil
}

// pageChunker emits chunks onto the given channel from a page
func (s *Source) pageChunker(ctx context.Context, client *s3.S3, chunksChan chan *sources.Chunk, bucket string, page *s3.ListObjectsV2Output, errorCount *sync.Map) {
	sem := semaphore.NewWeighted(int64(s.concurrency))
	var wg sync.WaitGroup
	for _, obj := range page.Contents {
		if common.IsDone(ctx) {
			return
		}

		err := sem.Acquire(ctx, 1)
		if err != nil {
			log.WithError(err).Error("could not acquire semaphore")
			continue
		}
		wg.Add(1)
		go func(ctx context.Context, wg *sync.WaitGroup, sem *semaphore.Weighted, obj *s3.Object) {
			defer sem.Release(1)
			defer wg.Done()
			//defer log.Debugf("DONE - %s", *obj.Key)

			if (*obj.Key)[len(*obj.Key)-1:] == "/" {
				return
			}
			//log.Debugf("Object: %s", *obj.Key)

			path := strings.Split(*obj.Key, "/")
			prefix := strings.Join(path[:len(path)-1], "/")

			nErr, ok := errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 3 {
				log.Debugf("Skipped: %s", *obj.Key)
				return
			}

			// ignore large files
			if *obj.Size > int64(10*common.MB) {
				return
			}

			//file is 0 bytes - likely no permissions - skipping
			if *obj.Size == 0 {
				return
			}

			//files break with spaces, must replace with +
			//objKey := strings.ReplaceAll(*obj.Key, " ", "+")
			ctx, cancel := context.WithTimeout(ctx, time.Second*5)
			defer cancel()
			res, err := client.GetObjectWithContext(ctx, &s3.GetObjectInput{
				Bucket: &bucket,
				Key:    obj.Key,
			})
			if err != nil {
				if !strings.Contains(err.Error(), "AccessDenied") {
					s.log.WithError(err).Errorf("could not get S3 object: %s", *obj.Key)
				}

				nErr, ok := errorCount.Load(prefix)
				if !ok {
					nErr = 0
				}
				if nErr.(int) > 3 {
					log.Debugf("Skipped: %s", *obj.Key)
					return
				}
				nErr = nErr.(int) + 1
				errorCount.Store(prefix, nErr)
				//too many consective errors on this page
				if nErr.(int) > 3 {
					s.log.Warnf("Too many consecutive errors. Blacklisting %s", prefix)
				}
				log.Debugf("Error Counts: %s:%s", prefix, nErr)
				return
			}
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				s.log.WithError(err).Error("could not read S3 object body")
				nErr, ok := errorCount.Load(prefix)
				if !ok {
					nErr = 0
				}
				//too many consective errors on this page
				if nErr.(int) > 3 {
					log.Debugf("Skipped: %s", *obj.Key)
					return
				}
				nErr = nErr.(int) + 1
				errorCount.Store(prefix, nErr)

				if nErr.(int) > 3 {
					s.log.Warnf("Too many consecutive errors. Blacklisting %s", prefix)
				}
				return
			}

			// ignore files that don't have secrets
			if common.SkipFile(*obj.Key, body) {
				return
			}

			email := "Unknown"
			if obj.Owner != nil {
				email = *obj.Owner.DisplayName
			}
			modified := obj.LastModified.String()
			chunk := sources.Chunk{
				SourceType: s.Type(),
				SourceName: s.name,
				SourceID:   s.SourceID(),
				Data:       body,
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
			nErr, ok = errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 0 {
				errorCount.Store(prefix, 0)
			}
			chunksChan <- &chunk
		}(ctx, &wg, sem, obj)
	}
	wg.Wait()
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
