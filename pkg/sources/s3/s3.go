package s3

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sts"
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

const (
	defaultAWSRegion     = "us-east-1"
	defaultMaxObjectSize = 250 * 1024 * 1024 // 250 MiB
	maxObjectSizeLimit   = 250 * 1024 * 1024 // 250 MiB
)

type Source struct {
	name        string
	sourceId    int64
	jobId       int64
	verify      bool
	concurrency int
	log         logr.Logger
	sources.Progress
	errorCount    *sync.Map
	conn          *sourcespb.S3
	jobPool       *errgroup.Group
	maxObjectSize int64
	sources.CommonSourceUnitUnmarshaller
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.Validator = (*Source)(nil)

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

	s.setMaxObjectSize(conn.GetMaxObjectSize())

	return nil
}

func (s *Source) Validate(ctx context.Context) []error {
	var errors []error
	visitor := func(c context.Context, defaultRegionClient *s3.S3, roleArn string, buckets []string) {
		roleErrs := s.validateBucketAccess(c, defaultRegionClient, roleArn, buckets)
		if len(roleErrs) > 0 {
			errors = append(errors, roleErrs...)
		}
	}

	err := s.visitRoles(ctx, visitor)
	if err != nil {
		errors = append(errors, err)
	}

	return errors
}

// setMaxObjectSize sets the maximum size of objects that will be scanned. If
// not set, set to a negative number, or set larger than the
// maxObjectSizeLimit, the defaultMaxObjectSizeLimit will be used.
func (s *Source) setMaxObjectSize(maxObjectSize int64) {
	if maxObjectSize <= 0 || maxObjectSize > maxObjectSizeLimit {
		s.maxObjectSize = defaultMaxObjectSize
	} else {
		s.maxObjectSize = maxObjectSize
	}
}

func (s *Source) newClient(region, roleArn string) (*s3.S3, error) {
	cfg := aws.NewConfig()
	cfg.CredentialsChainVerboseErrors = aws.Bool(true)
	cfg.Region = aws.String(region)

	if roleArn == "" {
		switch cred := s.conn.GetCredential().(type) {
		case *sourcespb.S3_SessionToken:
			cfg.Credentials = credentials.NewStaticCredentials(cred.SessionToken.Key, cred.SessionToken.Secret, cred.SessionToken.SessionToken)
		case *sourcespb.S3_AccessKey:
			cfg.Credentials = credentials.NewStaticCredentials(cred.AccessKey.Key, cred.AccessKey.Secret, "")
		case *sourcespb.S3_Unauthenticated:
			cfg.Credentials = credentials.AnonymousCredentials
		case *sourcespb.S3_CloudEnvironment:
			// Nothing needs to be done!
		default:
			return nil, errors.Errorf("invalid configuration given for %s source", s.name)
		}
	} else {
		sess, err := session.NewSession(cfg)
		if err != nil {
			return nil, err
		}

		stsClient := sts.New(sess)
		cfg.Credentials = stscreds.NewCredentialsWithClient(stsClient, roleArn, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = "trufflehog"
		})
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

// IAM identity needs s3:ListBuckets permission
func (s *Source) getBucketsToScan(client *s3.S3) ([]string, error) {
	if len(s.conn.Buckets) > 0 {
		return s.conn.Buckets, nil
	}

	res, err := client.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	var bucketsToScan []string
	for _, bucket := range res.Buckets {
		bucketsToScan = append(bucketsToScan, *bucket.Name)
	}
	return bucketsToScan, nil
}

func (s *Source) scanBuckets(ctx context.Context, client *s3.S3, role string, bucketsToScan []string, chunksChan chan *sources.Chunk) {
	objectCount := uint64(0)

	logger := s.log
	if role != "" {
		logger = logger.WithValues("roleArn", role)
	}

	for i, bucket := range bucketsToScan {
		logger := logger.WithValues("bucket", bucket)

		if common.IsDone(ctx) {
			return
		}

		s.SetProgressComplete(i, len(bucketsToScan), fmt.Sprintf("Bucket: %s", bucket), "")
		logger.Info("Scanning bucket")

		regionalClient, err := s.getRegionalClientForBucket(ctx, client, role, bucket)
		if err != nil {
			logger.Error(err, "could not get regional client for bucket")
			continue
		}

		errorCount := sync.Map{}

		err = regionalClient.ListObjectsV2PagesWithContext(
			ctx, &s3.ListObjectsV2Input{Bucket: &bucket},
			func(page *s3.ListObjectsV2Output, last bool) bool {
				s.pageChunker(ctx, regionalClient, chunksChan, bucket, page, &errorCount, i+1, &objectCount)
				return true
			})

		if err != nil {
			if role == "" {
				logger.Error(err, "could not list objects in bucket")
			} else {
				// Our documentation blesses specifying a role to assume without specifying buckets to scan, which will
				// often cause this to happen a lot (because in that case the scanner tries to scan every bucket in the
				// account, but the role probably doesn't have access to all of them). This makes it expected behavior
				// and therefore not an error.
				logger.V(3).Info("could not list objects in bucket",
					"err", err)
			}
		}
	}
	s.SetProgressComplete(len(bucketsToScan), len(bucketsToScan), fmt.Sprintf("Completed scanning source %s. %d objects scanned.", s.name, objectCount), "")
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	visitor := func(c context.Context, defaultRegionClient *s3.S3, roleArn string, buckets []string) {
		s.scanBuckets(c, defaultRegionClient, roleArn, buckets, chunksChan)
	}

	return s.visitRoles(ctx, visitor)
}

func (s *Source) getRegionalClientForBucket(ctx context.Context, defaultRegionClient *s3.S3, role, bucket string) (*s3.S3, error) {
	region, err := s3manager.GetBucketRegionWithClient(ctx, defaultRegionClient, bucket)
	if err != nil {
		return nil, errors.WrapPrefix(err, "could not get s3 region for bucket", 0)
	}

	if region == defaultAWSRegion {
		return defaultRegionClient, nil
	}

	regionalClient, err := s.newClient(region, role)
	if err != nil {
		return nil, errors.WrapPrefix(err, "could not create regional s3 client", 0)
	}

	return regionalClient, nil
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
		if *obj.Size > s.maxObjectSize {
			s.log.V(3).Info("Skipping %d byte file (over maxObjectSize limit)", "object", *obj.Key)
			continue
		}

		// file empty file
		if *obj.Size == 0 {
			s.log.V(5).Info("Skipping 0 byte file", "object", *obj.Key)
			continue
		}

		// skip incompatible extensions
		if common.SkipFile(*obj.Key) {
			s.log.V(5).Info("Skipping file with incompatible extension", "object", *obj.Key)
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
			if handlers.HandleFile(ctx, reader, chunkSkel, chunksChan) {
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

func (s *Source) validateBucketAccess(ctx context.Context, client *s3.S3, roleArn string, buckets []string) []error {
	shouldHaveAccessToAllBuckets := roleArn == ""
	wasAbleToListAnyBucket := false
	var errors []error

	for _, bucket := range buckets {
		if common.IsDone(ctx) {
			return append(errors, ctx.Err())
		}

		regionalClient, err := s.getRegionalClientForBucket(ctx, client, roleArn, bucket)
		if err != nil {
			errors = append(errors, fmt.Errorf("could not get regional client for bucket %q: %w", bucket, err))
			continue
		}

		_, err = regionalClient.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: &bucket})

		if err == nil {
			wasAbleToListAnyBucket = true
		} else if shouldHaveAccessToAllBuckets {
			errors = append(errors, fmt.Errorf("could not list objects in bucket %q: %w", bucket, err))
		}
	}

	if !wasAbleToListAnyBucket {
		if roleArn == "" {
			errors = append(errors, fmt.Errorf("could not list objects in any bucket"))
		} else {
			errors = append(errors, fmt.Errorf("role %q could not list objects in any bucket", roleArn))
		}
	}

	return errors
}

func (s *Source) visitRoles(ctx context.Context, f func(c context.Context, defaultRegionClient *s3.S3, roleArn string, buckets []string)) error {
	roles := s.conn.Roles
	if len(roles) == 0 {
		roles = []string{""}
	}

	for _, role := range roles {
		client, err := s.newClient(defaultAWSRegion, role)
		if err != nil {
			return errors.WrapPrefix(err, "could not create s3 client", 0)
		}

		bucketsToScan, err := s.getBucketsToScan(client)
		if err != nil {
			return fmt.Errorf("role %q could not list any s3 buckets for scanning: %w", role, err)
		}

		f(ctx, client, role, bucketsToScan)
	}

	return nil
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
