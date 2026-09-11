package s3

import (
	stdctx "context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-errors/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_S3

	defaultAWSRegion     = "us-east-1"
	defaultMaxObjectSize = 250 * 1024 * 1024 // 250 MiB
	maxObjectSizeLimit   = 250 * 1024 * 1024 // 250 MiB
)

type Source struct {
	name        string
	sourceID    sources.SourceID
	jobID       sources.JobID
	verify      bool
	concurrency int
	conn        *sourcespb.S3

	sources.Progress
	metricsCollector metricsCollector

	errorCount    *sync.Map
	jobPool       *errgroup.Group
	maxObjectSize int64
	// endpoint is the S3-compatible service to scan, or nil for AWS S3.
	endpoint *url.URL
	// objectFilter is never nil after Init.
	objectFilter *objectFilter
}

// Ensure the Source satisfies the interfaces at compile time
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.Validator = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

// Type returns the type of source
func (s *Source) Type() sourcespb.SourceType { return SourceType }

func (s *Source) SourceID() sources.SourceID { return s.sourceID }

func (s *Source) JobID() sources.JobID { return s.jobID }

// Init returns an initialized AWS source
func (s *Source) Init(
	ctx context.Context,
	name string,
	jobID sources.JobID,
	sourceID sources.SourceID,
	verify bool,
	connection *anypb.Any,
	concurrency int,
) error {
	s.name = name
	s.sourceID = sourceID
	s.jobID = jobID
	s.verify = verify
	s.concurrency = concurrency
	s.errorCount = &sync.Map{}
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.S3
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}
	s.conn = &conn

	endpoint, err := normalizeEndpoint(conn.GetEndpoint())
	if err != nil {
		return err
	}
	s.endpoint = endpoint

	s.metricsCollector = metricsInstance

	s.setMaxObjectSize(conn.GetMaxObjectSize())

	if len(conn.GetBuckets()) > 0 && len(conn.GetIgnoreBuckets()) > 0 {
		return errors.New("either a bucket include list or a bucket ignore list can be specified, but not both")
	}

	filter, err := newObjectFilter(
		conn.GetIncludePrefixes(),
		conn.GetExcludePrefixes(),
		conn.GetIncludeExtensions(),
		conn.GetExcludeExtensions(),
	)
	if err != nil {
		return err
	}
	s.objectFilter = filter

	if filter.isConfigured() {
		ctx.Logger().V(1).Info("Object filter configured",
			"include_prefixes", filter.includePrefixes,
			"exclude_prefixes", filter.excludePrefixes,
			"include_extensions", filter.includeExtensions,
			"exclude_extensions", filter.excludeExtensions)
	}

	return nil
}

func (s *Source) Validate(ctx context.Context) []error {
	var errs []error
	visitor := func(c context.Context, defaultRegionClient *s3.Client, roleArn string, buckets []string) error {
		roleErrs := s.validateBucketAccess(c, defaultRegionClient, roleArn, buckets)
		if len(roleErrs) > 0 {
			errs = append(errs, roleErrs...)
		}
		return nil
	}

	if err := s.visitRoles(ctx, visitor); err != nil {
		errs = append(errs, err)
	}

	return errs
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

// normalizeEndpoint parses the configured endpoint of an S3-compatible
// service, returning nil for the empty endpoint that means AWS S3. A scheme is
// assumed when one is missing, because the endpoint is user-entered and the AWS
// SDK rejects a bare host with an error that does not say so.
func normalizeEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" {
		return nil, nil
	}

	parsed, err := url.Parse(endpoint)

	// Without a scheme, the endpoint either parses as a path with no host or,
	// when it carries a port, fails to parse at all. Retry those as URLs, but
	// only when no scheme was given, so that a malformed one is still reported
	// rather than buried under a second scheme.
	if !strings.Contains(endpoint, "://") && (err != nil || parsed.Host == "") {
		parsed, err = url.Parse("https://" + endpoint)
	}
	if err != nil {
		return nil, fmt.Errorf("could not parse endpoint %q: %w", endpoint, err)
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("endpoint %q has no host; expected something like https://s3.internal.example.com", endpoint)
	}

	return parsed, nil
}

// defaultRegion returns the region used to sign requests for buckets whose own
// region has not been discovered.
func (s *Source) defaultRegion() string {
	if region := s.conn.GetRegion(); region != "" {
		return region
	}
	return defaultAWSRegion
}

func (s *Source) newClient(ctx context.Context, region, roleArn string) (*s3.Client, error) {
	var credsProvider aws.CredentialsProvider
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.S3_SessionToken:
		credsProvider = credentials.NewStaticCredentialsProvider(
			cred.SessionToken.GetKey(),
			cred.SessionToken.GetSecret(),
			cred.SessionToken.GetSessionToken(),
		)
		log.RedactGlobally(cred.SessionToken.GetSecret())
		log.RedactGlobally(cred.SessionToken.GetSessionToken())
	case *sourcespb.S3_AccessKey:
		credsProvider = credentials.NewStaticCredentialsProvider(cred.AccessKey.GetKey(), cred.AccessKey.GetSecret(), "")
		log.RedactGlobally(cred.AccessKey.GetSecret())
	case *sourcespb.S3_Unauthenticated:
		credsProvider = aws.AnonymousCredentials{}
	default:
		// In all other cases, the AWS SDK will follow its normal waterfall logic to pick up credentials (i.e. they can
		// come from the environment or the credentials file or whatever else AWS gets up to).
	}

	if roleArn != "" {
		// The config loaded here will be used to retrieve and refresh temporary credentials from AssumeRole
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithCredentialsProvider(credsProvider))
		if err != nil {
			return nil, err
		}

		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, roleArn, func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = "trufflehog"
		})
		// From https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html#specify-credentials-programmatically:
		//   "If you explicitly configure a provider on aws.Config directly,
		//    you must also explicitly wrap the provider with this type using NewCredentialsCache"
		credsProvider = aws.NewCredentialsCache(provider)
	}

	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credsProvider),
	)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg, func(options *s3.Options) {
		options.DisableLogOutputChecksumValidationSkipped = true
		if s.endpoint != nil {
			options.BaseEndpoint = aws.String(s.endpoint.String())
			// S3-compatible services rarely publish the wildcard DNS that
			// virtual-hosted addressing needs.
			options.UsePathStyle = true
		}
	}), nil
}

// getBucketsToScan returns a list of S3 buckets to scan.
// If the connection has a list of buckets specified, those are returned.
// Otherwise, it lists all buckets the client has access to and filters out the ignored ones.
// The list of buckets is sorted lexicographically to ensure consistent ordering,
// which allows resuming scanning from the same place if the scan is interrupted.
//
// Note: The IAM identity needs the s3:ListBuckets permission.
func (s *Source) getBucketsToScan(ctx context.Context, client *s3.Client) ([]string, error) {
	if buckets := s.conn.GetBuckets(); len(buckets) > 0 {
		slices.Sort(buckets)
		return buckets, nil
	}

	ignore := make(map[string]struct{}, len(s.conn.GetIgnoreBuckets()))
	for _, bucket := range s.conn.GetIgnoreBuckets() {
		ignore[bucket] = struct{}{}
	}

	res, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	var bucketsToScan []string
	for _, bucket := range res.Buckets {
		name := *bucket.Name
		if _, ignored := ignore[name]; !ignored {
			bucketsToScan = append(bucketsToScan, name)
		}
	}
	slices.Sort(bucketsToScan)

	return bucketsToScan, nil
}

// pageMetadata contains metadata about a single page of S3 objects being scanned.
type pageMetadata struct {
	bucket     string                  // The name of the S3 bucket being scanned
	role       string                  // The AWS role ARN used for scanning
	pageNumber int                     // Current page number in the pagination sequence
	client     *s3.Client              // AWS S3 client configured for the appropriate region
	page       *s3.ListObjectsV2Output // Contains the list of S3 objects in this page
}

// processingState tracks the state of concurrent S3 object processing.
type processingState struct {
	errorCount    *sync.Map // Thread-safe map tracking errors per prefix
	objectCount   *uint64   // Total number of objects processed
	filteredCount *uint64   // Total number of objects excluded by the object filter
}

// resumePosition tracks where to restart scanning S3 buckets and objects after an interruption.
// It encapsulates all the information needed to resume a scan from its last known position.
type resumePosition struct {
	bucket     string // The bucket name we were processing
	index      int    // Index in the buckets slice where we should resume
	startAfter string // The last processed object key within the bucket
	isNewScan  bool   // True if we're starting a fresh scan
	exactMatch bool   // True if we found the exact bucket we were previously processing
	role       string // The role used during the previous scan
}

// determineResumePosition calculates where to resume scanning from based on the last saved checkpoint
// and the current list of available buckets to scan. It handles several scenarios:
//
//  1. If getting the resume point fails or there is no previous bucket saved (CurrentBucket is empty),
//     we start a new scan from the beginning, this is the safest option.
//
//  2. If the previous bucket exists in our current scan list (exactMatch=true),
//     we resume from that exact position and use the StartAfter value
//     to continue from the last processed object within that bucket.
//
// 3. If the previous bucket is not found in our current scan list (exactMatch=false), this typically means:
//   - The bucket was deleted since our last scan
//   - The bucket was explicitly excluded from this scan's configuration
//   - The IAM role no longer has access to the bucket
//   - The bucket name changed due to a configuration update
//     In this case, we use binary search to find the closest position where the bucket would have been,
//     allowing us to resume from the nearest available point in our sorted bucket list rather than
//     restarting the entire scan.
func determineResumePosition(ctx context.Context, tracker *Checkpointer, buckets []string) resumePosition {
	resumePoint, err := tracker.ResumePoint(ctx)
	if err != nil {
		ctx.Logger().Error(err, "failed to get resume point; starting from the beginning")
		return resumePosition{isNewScan: true}
	}

	if resumePoint.CurrentBucket == "" {
		return resumePosition{isNewScan: true}
	}

	startIdx, found := slices.BinarySearch(buckets, resumePoint.CurrentBucket)
	return resumePosition{
		bucket:     resumePoint.CurrentBucket,
		startAfter: resumePoint.StartAfter,
		index:      startIdx,
		exactMatch: found,
		role:       resumePoint.Role,
	}
}

// scanBuckets scans the given buckets using the given role and adds the number
// of objects it scanned to totalObjectCount. The counter is owned by Chunks and
// shared across role passes so that the completion message reflects the whole
// scan, not just the last role's pass.
//
// Every bucket is attempted even if earlier ones fail, so one unreachable bucket
// cannot hide findings in the rest. Failures are returned together.
func (s *Source) scanBuckets(
	ctx context.Context,
	client *s3.Client,
	role string,
	bucketsToScan []string,
	chunksChan chan *sources.Chunk,
	totalObjectCount *uint64,
) error {
	if role != "" {
		ctx = context.WithValue(ctx, "role", role)
	}

	checkpointer := NewCheckpointer(ctx, &s.Progress, false)
	pos := determineResumePosition(ctx, checkpointer, bucketsToScan)
	switch {
	case pos.isNewScan:
		ctx.Logger().Info("Starting new scan from beginning")
	case !pos.exactMatch:
		ctx.Logger().Info(
			"Resume bucket no longer available, starting from closest position",
			"original_bucket", pos.bucket,
			"position", pos.index,
			"role", pos.role,
		)
	default:
		ctx.Logger().Info(
			"Resuming scan from previous scan's bucket",
			"bucket", pos.bucket,
			"position", pos.index,
			"role", pos.role,
		)
	}

	// Collected rather than returned immediately so one bad bucket does not cut
	// the pass short; the first failure also anchors resumption if the pass is
	// interrupted before those buckets get a retry.
	var (
		bucketErrs        []error
		firstFailedBucket string
	)

	bucketsToScanCount := len(bucketsToScan)
	for bucketIdx := pos.index; bucketIdx < bucketsToScanCount; bucketIdx++ {
		bucket := bucketsToScan[bucketIdx]

		s.SetProgressComplete(
			bucketIdx,
			len(bucketsToScan),
			fmt.Sprintf("Bucket: %s", bucket),
			s.EncodedResumeInfo,
		)

		var startAfter *string
		if bucket == pos.bucket && pos.startAfter != "" && role == pos.role {
			startAfter = &pos.startAfter
			ctx.Logger().V(3).Info(
				"Resuming bucket scan",
				"start_after", pos.startAfter,
				"bucket", bucket,
			)
		}

		objectCount, err := s.scanBucket(ctx, client, role, bucket, sources.ChanReporter{Ch: chunksChan}, startAfter, checkpointer)
		// Added even on failure: a bucket that stopped part way still scanned what
		// it reports.
		*totalObjectCount += objectCount
		if err != nil {
			if isContextCancellation(err) {
				ctx.Logger().V(3).Info("bucket scan interrupted", "bucket", bucket, "err", err)
				// Returns before the completion call below so resume info survives,
				// rewound to the earliest failure first: resuming past a bucket that
				// still needs another attempt drops it from the scan entirely.
				if firstFailedBucket != "" {
					if rewindErr := checkpointer.ResumeFrom(firstFailedBucket, role); rewindErr != nil {
						ctx.Logger().Error(rewindErr, "could not rewind resume point to failed bucket", "bucket", firstFailedBucket)
					}
				}
				return errors.Join(bucketErrs...)
			}
			bucketErrs = append(bucketErrs, err)
			if firstFailedBucket == "" {
				firstFailedBucket = bucket
			}
			continue
		}
	}

	// Resume info is cleared even when buckets failed: the checkpointer already
	// advanced past them, so keeping it would make the retry skip them.
	s.SetProgressComplete(
		len(bucketsToScan),
		len(bucketsToScan),
		fmt.Sprintf("Completed scanning source %s. %d objects scanned.", s.name, *totalObjectCount),
		"",
	)

	return errors.Join(bucketErrs...)
}

func (s *Source) scanBucket(
	ctx context.Context,
	client *s3.Client,
	role string,
	bucket string,
	reporter sources.ChunkReporter,
	startAfter *string,
	checkpointer *Checkpointer,
) (uint64, error) {
	s.metricsCollector.RecordBucketForRole(role)

	ctx = context.WithValue(ctx, "bucket", bucket)

	if common.IsDone(ctx) {
		// Returned so callers can tell an interrupted bucket from a finished one;
		// Chunks and ChunkUnit turn it back into a clean stop.
		ctx.Logger().V(3).Info("context done, stopping bucket scan", "err", ctx.Err())
		return 0, ctx.Err()
	}

	ctx.Logger().V(3).Info("Scanning bucket")

	regionalClient, err := s.getRegionalClientForBucket(ctx, client, role, bucket)
	if err != nil {
		// Checked ahead of the split below: a cancellation says nothing about the
		// bucket, so classifying it as an expected denial would report an
		// interrupted bucket as a finished one.
		if isContextCancellation(err) {
			return 0, err
		}
		// Same expected-vs-fatal split as listing below: enumeration walks every
		// bucket and will fail region lookup on many of them.
		if s.listErrorsAreExpected() {
			ctx.Logger().V(3).Info("skipping enumerated bucket: could not resolve its region", "err", err)
			return 0, nil
		}
		return 0, fmt.Errorf("could not resolve region for configured bucket %q: %w", bucket, err)
	}

	errorCount := sync.Map{}

	input := &s3.ListObjectsV2Input{Bucket: &bucket}
	if startAfter != nil {
		input.StartAfter = startAfter
	}

	pageNumber := 1
	paginator := s3.NewListObjectsV2Paginator(regionalClient, input)
	var objectCount, filteredCount uint64
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			// Checked before the expected-vs-fatal split for the same reason as the
			// region lookup above.
			if isContextCancellation(err) {
				return objectCount, err
			}
			s.metricsCollector.RecordBucketListError(bucket, role)
			if s.listErrorsAreExpected() {
				// Scanning without naming buckets is supported, and the identity is
				// expected to be denied on some of what it enumerates.
				ctx.Logger().V(3).Info("skipping enumerated bucket: could not list objects", "err", err)
				return objectCount, nil
			}
			// Returned so a named bucket that cannot be listed fails the scan rather
			// than passing as an empty one. May also be a lazily resolved STS failure.
			return objectCount, fmt.Errorf("could not list objects in configured bucket %q: %w", bucket, err)
		}
		pageMetadata := pageMetadata{
			bucket:     bucket,
			role:       role,
			pageNumber: pageNumber,
			client:     regionalClient,
			page:       output,
		}
		processingState := processingState{
			errorCount:    &errorCount,
			objectCount:   &objectCount,
			filteredCount: &filteredCount,
		}
		s.pageChunker(ctx, pageMetadata, processingState, reporter, checkpointer)

		pageNumber++
	}

	// A filter that excludes everything otherwise looks exactly like a clean scan
	// of an empty bucket, so say so rather than finishing silently.
	if objectCount == 0 && filteredCount > 0 {
		ctx.Logger().Info("Scanned no objects in bucket", "excluded_by_object_filter", filteredCount)
	}

	return objectCount, nil
}

// listErrorsAreExpected reports whether failing to list a bucket should be
// suppressed. Denials are routine when buckets come from enumeration, but a
// bucket the user named is a target they expect to reach.
func (s *Source) listErrorsAreExpected() bool {
	return len(s.conn.GetBuckets()) == 0
}

// isContextCancellation reports whether err is the scan being stopped rather than
// a target failing. Unwraps, so a cancellation wrapped by the AWS SDK still matches.
func isContextCancellation(err error) bool {
	return errors.Is(err, stdctx.Canceled) || errors.Is(err, stdctx.DeadlineExceeded)
}

// Chunks emits chunks of bytes over a channel. Failures to reach a named bucket
// are returned; an interrupted scan is not a failure and returns nil.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	var totalObjectCount uint64

	// visitRoles stops at the first visitor error, so failures are recorded here
	// instead: a bucket one role cannot reach is often reachable under a later one.
	var roleErrs []error
	visitor := func(c context.Context, defaultRegionClient *s3.Client, roleArn string, buckets []string) error {
		// Without this the remaining roles would each set up a client only to find
		// the context already done.
		if common.IsDone(c) {
			return c.Err()
		}

		if err := s.scanBuckets(c, defaultRegionClient, roleArn, buckets, chunksChan, &totalObjectCount); err != nil {
			roleErrs = append(roleErrs, err)
		}

		return nil
	}

	// Role setup and bucket discovery can also fail from cancellation, so the
	// filter belongs here rather than only around scanBuckets.
	if err := s.visitRoles(ctx, visitor); err != nil && !isContextCancellation(err) {
		return err
	}

	return errors.Join(roleErrs...)
}

func (s *Source) getRegionalClientForBucket(
	ctx context.Context,
	defaultRegionClient *s3.Client,
	role string,
	bucket string,
) (*s3.Client, error) {
	// GetBucketRegion is an AWS-only API, and a custom endpoint serves every
	// bucket itself, so there is no per-bucket region to discover.
	if s.endpoint != nil {
		return defaultRegionClient, nil
	}

	region, err := s3manager.GetBucketRegion(ctx, defaultRegionClient, bucket)
	if err != nil {
		return nil, fmt.Errorf("could not get s3 region for bucket: %s: %w", bucket, err)
	}

	if region == s.defaultRegion() {
		return defaultRegionClient, nil
	}

	regionalClient, err := s.newClient(ctx, region, role)
	if err != nil {
		return nil, fmt.Errorf("could not create regional s3 client for bucket %s: %w", bucket, err)
	}

	return regionalClient, nil
}

// pageChunker emits chunks onto the given channel from a page.
func (s *Source) pageChunker(
	ctx context.Context,
	metadata pageMetadata,
	state processingState,
	reporter sources.ChunkReporter,
	checkpointer *Checkpointer,
) {
	checkpointer.Reset() // Reset the checkpointer for each PAGE
	ctx = context.WithValues(ctx, "bucket", metadata.bucket, "page_number", metadata.pageNumber)
	for objIdx, obj := range metadata.page.Contents {
		octx := context.WithValues(ctx, "key", *obj.Key, "size", *obj.Size)
		if common.IsDone(octx) {
			return
		}

		// Skip objects excluded by the configured prefixes or extensions.
		if !s.objectFilter.shouldInclude(*obj.Key) {
			atomic.AddUint64(state.filteredCount, 1)
			octx.Logger().V(5).Info("Skipping filtered object")
			s.metricsCollector.RecordObjectSkipped(metadata.bucket, "object_filter", float64(*obj.Size))
			if err := checkpointer.UpdateObjectCompletion(octx, objIdx, metadata.bucket, metadata.role, metadata.page.Contents); err != nil {
				octx.Logger().Error(err, "could not update progress for filtered object")
			}
			continue
		}

		// Skip GLACIER and GLACIER_IR objects.
		if obj.StorageClass == s3types.ObjectStorageClassGlacier || obj.StorageClass == s3types.ObjectStorageClassGlacierIr {
			octx.Logger().V(5).Info("Skipping object in storage class", "storage_class", obj.StorageClass)
			s.metricsCollector.RecordObjectSkipped(metadata.bucket, "storage_class", float64(*obj.Size))
			if err := checkpointer.UpdateObjectCompletion(octx, objIdx, metadata.bucket, metadata.role, metadata.page.Contents); err != nil {
				octx.Logger().Error(err, "could not update progress for glacier object")
			}
			continue
		}

		// Ignore large files.
		if *obj.Size > s.maxObjectSize {
			octx.Logger().V(5).Info("Skipping large file", "max_object_size", s.maxObjectSize)
			s.metricsCollector.RecordObjectSkipped(metadata.bucket, "size_limit", float64(*obj.Size))
			if err := checkpointer.UpdateObjectCompletion(octx, objIdx, metadata.bucket, metadata.role, metadata.page.Contents); err != nil {
				octx.Logger().Error(err, "could not update progress for large file")
			}
			continue
		}

		// File empty file.
		if *obj.Size == 0 {
			octx.Logger().V(5).Info("Skipping empty file")
			s.metricsCollector.RecordObjectSkipped(metadata.bucket, "empty_file", 0)
			if err := checkpointer.UpdateObjectCompletion(octx, objIdx, metadata.bucket, metadata.role, metadata.page.Contents); err != nil {
				octx.Logger().Error(err, "could not update progress for empty file")
			}
			continue
		}

		// Skip incompatible extensions.
		if common.SkipFile(*obj.Key) {
			octx.Logger().V(5).Info("Skipping file with incompatible extension")
			s.metricsCollector.RecordObjectSkipped(metadata.bucket, "incompatible_extension", float64(*obj.Size))
			if err := checkpointer.UpdateObjectCompletion(octx, objIdx, metadata.bucket, metadata.role, metadata.page.Contents); err != nil {
				octx.Logger().Error(err, "could not update progress for incompatible file")
			}
			continue
		}

		s.jobPool.Go(func() error {
			defer common.RecoverWithExit(octx)
			if common.IsDone(octx) {
				return octx.Err()
			}

			if strings.HasSuffix(*obj.Key, "/") {
				octx.Logger().V(5).Info("Skipping directory")
				s.metricsCollector.RecordObjectSkipped(metadata.bucket, "directory", float64(*obj.Size))
				return nil
			}

			path := strings.Split(*obj.Key, "/")
			prefix := strings.Join(path[:len(path)-1], "/")

			nErr, ok := state.errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 3 {
				octx.Logger().V(2).Info("Skipped due to excessive errors")
				return nil
			}
			// Make sure we use a separate context for the GetObjectWithContext call.
			// This ensures that the timeout is isolated and does not affect any downstream operations. (e.g. HandleFile)
			const getObjectTimeout = 30 * time.Second
			objCtx, cancel := context.WithTimeout(octx, getObjectTimeout)
			defer cancel()

			res, err := metadata.client.GetObject(objCtx, &s3.GetObjectInput{
				Bucket: &metadata.bucket,
				Key:    obj.Key,
			})
			if err != nil {
				if strings.Contains(err.Error(), "AccessDenied") {
					octx.Logger().Info("could not get S3 object; access denied", "err", err)
					s.metricsCollector.RecordObjectSkipped(metadata.bucket, "access_denied", float64(*obj.Size))
				} else {
					octx.Logger().Info("could not get S3 object", "err", err)
					s.metricsCollector.RecordObjectError(metadata.bucket)
				}
				// According to the documentation for GetObjectWithContext,
				// the response can be non-nil even if there was an error.
				// It's uncertain if the body will be nil in such cases,
				// but we'll close it if it's not.
				if res != nil && res.Body != nil {
					_ = res.Body.Close()
				}

				nErr, ok := state.errorCount.Load(prefix)
				if !ok {
					nErr = 0
				}
				if nErr.(int) > 3 {
					octx.Logger().V(3).Info("Skipped due to excessive errors")
					return nil
				}
				nErr = nErr.(int) + 1
				state.errorCount.Store(prefix, nErr)
				// too many consecutive errors on this page
				if nErr.(int) > 3 {
					octx.Logger().V(2).Info("Too many consecutive errors, excluding prefix", "prefix", prefix)
				}
				return nil
			}
			defer func() { _ = res.Body.Close() }()

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
							Bucket:    metadata.bucket,
							File:      sanitizer.UTF8(*obj.Key),
							Link:      sanitizer.UTF8(s.objectLink(metadata.bucket, metadata.client.Options().Region, *obj.Key)),
							Email:     sanitizer.UTF8(email),
							Timestamp: sanitizer.UTF8(modified),
						},
					},
				},
				SourceVerify: s.verify,
			}

			if err := handlers.HandleFile(octx, res.Body, chunkSkel, reporter); err != nil {
				octx.Logger().Error(err, "error handling file")
				s.metricsCollector.RecordObjectError(metadata.bucket)
				return nil
			}
			atomic.AddUint64(state.objectCount, 1)
			octx.Logger().V(5).Info("S3 object scanned.", "object_count", state.objectCount)
			nErr, ok = state.errorCount.Load(prefix)
			if !ok {
				nErr = 0
			}
			if nErr.(int) > 0 {
				state.errorCount.Store(prefix, 0)
			}
			// Update progress after successful processing.
			if err := checkpointer.UpdateObjectCompletion(octx, objIdx, metadata.bucket, metadata.role, metadata.page.Contents); err != nil {
				octx.Logger().Error(err, "could not update progress for scanned object")
			}
			s.metricsCollector.RecordObjectScanned(metadata.bucket, float64(*obj.Size))
			return nil
		})
	}
	_ = s.jobPool.Wait()
}

func (s *Source) validateBucketAccess(ctx context.Context, client *s3.Client, roleArn string, buckets []string) []error {
	shouldHaveAccessToAllBuckets := roleArn == ""
	wasAbleToListAnyBucket := false
	var errs []error

	for _, bucket := range buckets {
		if common.IsDone(ctx) {
			return append(errs, ctx.Err())
		}

		regionalClient, err := s.getRegionalClientForBucket(ctx, client, roleArn, bucket)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not get regional client for bucket %q: %w", bucket, err))
			continue
		}

		_, err = regionalClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		if err == nil {
			wasAbleToListAnyBucket = true
		} else if shouldHaveAccessToAllBuckets {
			errs = append(errs, fmt.Errorf("could not list objects in bucket %q: %w", bucket, err))
		}
	}

	if !wasAbleToListAnyBucket {
		if roleArn == "" {
			errs = append(errs, errors.New("could not list objects in any bucket"))
		} else {
			errs = append(errs, fmt.Errorf("role %q could not list objects in any bucket", roleArn))
		}
	}

	return errs
}

// visitRoles iterates over the configured AWS roles and calls the provided function
// for each role, passing in the default S3 client, the role ARN, and the list of
// buckets to scan.
//
// The provided function parameter typically implements the core scanning logic
// and must handle context cancellation appropriately.
//
// If no roles are configured, it will call the function with an empty role ARN.
func (s *Source) visitRoles(
	ctx context.Context,
	f func(c context.Context, defaultRegionClient *s3.Client, roleArn string, buckets []string) error,
) error {
	roles := s.conn.GetRoles()
	if len(roles) == 0 {
		roles = []string{""}
	}

	for _, role := range roles {
		s.metricsCollector.RecordRoleScanned(role)

		client, err := s.newClient(ctx, s.defaultRegion(), role)
		if err != nil {
			return fmt.Errorf("could not create s3 client: %w", err)
		}

		bucketsToScan, err := s.getBucketsToScan(ctx, client)
		if err != nil {
			return fmt.Errorf("role %q could not list any s3 buckets for scanning: %w", role, err)
		}

		if err := f(ctx, client, role, bucketsToScan); err != nil {
			return err
		}
	}

	return nil
}

// objectLink creates a URL for an object. AWS buckets get a
// virtual-hosted–style URI, which has the format:
// https://[bucket-name].s3.[region-code].amazonaws.com/[key-name]
//
// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html#virtual-hosted-style-access
//
// A custom endpoint gets a path-style link, matching how the client addresses
// it, so the link resolves the same way the scan did.
func (s *Source) objectLink(bucket, region, key string) string {
	if s.endpoint == nil {
		return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, region, key)
	}

	link := *s.endpoint
	link.Path = strings.TrimSuffix(link.Path, "/") + "/" + bucket + "/" + key
	return link.String()
}

// Enumerate implements SourceUnitEnumerator interface. This implementation visits
// each configured role and passes each s3 bucket as a source unit
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	visitor := func(c context.Context, defaultRegionClient *s3.Client, roleArn string, buckets []string) error {
		for _, bucket := range buckets {
			if common.IsDone(ctx) {
				return ctx.Err()
			}

			unit := S3SourceUnit{
				Bucket: bucket,
				Role:   roleArn,
			}

			if err := reporter.UnitOk(ctx, unit); err != nil {
				return err
			}
		}
		return nil
	}

	return s.visitRoles(ctx, visitor)
}

// ChunkUnit implements SourceUnitChunker interface. This implementation scans
// the given S3 bucket source unit and emits chunks for each object found.
// It supports sub-unit resumption by utilizing the checkpointer to track progress.
// Listing failures for a named bucket are returned; resume info is kept unless
// the unit scanned to completion.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	// Filtered at this single exit because cancellation can surface from client
	// setup as well as from the scan itself.
	if err := s.chunkUnit(ctx, unit, reporter); err != nil && !isContextCancellation(err) {
		return err
	}

	return nil
}

// chunkUnit scans one bucket unit, clearing resume info only on a complete scan so
// that any failure lets a retry continue from the last checkpoint.
func (s *Source) chunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	s3unit, ok := unit.(S3SourceUnit)
	if !ok {
		return fmt.Errorf("expected *S3SourceUnit, got %T", unit)
	}
	// unitID is a combination of bucket name and role ARN
	unitID, _ := s3unit.SourceUnitID()
	defaultClient, err := s.newClient(ctx, s.defaultRegion(), s3unit.Role)
	if err != nil {
		return fmt.Errorf("could not create s3 client for bucket %s and role %s: %w", s3unit.Bucket, s3unit.Role, err)
	}

	checkpointer := NewCheckpointer(ctx, &s.Progress, true)

	var startAfterPtr *string
	startAfter := s.GetEncodedResumeInfoFor(unitID)
	if startAfter != "" {
		ctx.Logger().V(3).Info(
			"Resuming unit scan",
			"start_after", startAfter,
			"unitID", unitID,
		)
		startAfterPtr = &startAfter
	}
	if _, err = s.scanBucket(ctx, defaultClient, s3unit.Role, s3unit.Bucket, reporter, startAfterPtr, checkpointer); err != nil {
		return err
	}

	s.ClearEncodedResumeInfoFor(unitID)

	return nil
}

// It accepts three shapes: the persisted envelope carrying unit_data
// (round-trips the unit exactly), the envelope without unit_data (rebuilt from id),
// and a bare S3SourceUnit.
func (s *Source) UnmarshalSourceUnit(data []byte) (sources.SourceUnit, error) {
	var envelope unitEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Kind == string(SourceUnitKindBucket) {
		if envelope.UnitData != "" {
			if decoded, err := base64.StdEncoding.DecodeString(envelope.UnitData); err == nil {
				var unit S3SourceUnit
				if json.Unmarshal(decoded, &unit) == nil && unit.Bucket != "" {
					return unit, nil
				}
			}
		}
		if envelope.ID != "" {
			if role, bucket := splitS3SourceUnitID(envelope.ID); bucket != "" {
				return S3SourceUnit{Bucket: bucket, Role: role}, nil
			}
		}
	}

	var unit S3SourceUnit
	if err := json.Unmarshal(data, &unit); err != nil {
		return nil, err
	}
	unitID, kind := unit.SourceUnitID()
	if unitID == "" || kind != SourceUnitKindBucket {
		return nil, fmt.Errorf("not an S3SourceUnit")
	}
	return unit, nil
}
