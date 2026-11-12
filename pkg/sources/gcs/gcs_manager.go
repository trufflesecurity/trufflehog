package gcs

import (
	aCtx "context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"cloud.google.com/go/storage"
	"github.com/gobwas/glob"
	"github.com/googleapis/gax-go/v2"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"golang.org/x/oauth2/google"
)

const (
	defaultMaxObjectSize = 10 * 1024 * 1024 // 10MB
	maxObjectSizeLimit   = 50 * 1024 * 1024 // 50MB
)

var defaultConcurrency = runtime.NumCPU()

// errObjectSkipped means the object was skipped on purpose, not that reading it failed.
var errObjectSkipped = errors.New("object skipped")

// bucketManager is a simplified *storage.Client wrapper.
// It provides only a subset of methods that are needed by the gcsManager.
type bucketManager interface {
	// Bucket returns a BucketHandle for the given bucket name.
	Bucket(name string) *storage.BucketHandle
	// Buckets returns an iterator over the buckets in the project.
	Buckets(ctx aCtx.Context, projectID string) *storage.BucketIterator
}

// gcsManager serves as simple facade for interacting with GCS.
// It's main purpose is to retrieve objects from GCS.
type gcsManager struct {
	projectID string
	withoutAuth,
	hasEnumerated bool

	concurrency int
	workerPool  *errgroup.Group

	maxObjectSize int64
	numBuckets    uint32
	numObjects    uint64

	includeBuckets,
	excludeBuckets,
	includeObjects,
	excludeObjects map[string]struct{}

	buckets map[string]bucket
	attr    *attributes

	client bucketManager
}

// bucket is a simplified *storage.BucketHandle wrapper.
// It also provides a mechanism for resuming an interrupted iteration.
// This reduces the number of objects that need to be re-processed.
type bucket struct {
	shouldInclude bool
	name          string
	// startOffset is the name of the object to resume from. (inclusive)
	// This works because GCS objects are sorted lexicographically.
	// If this is empty, the iteration will start from the beginning.
	startOffset string
	*storage.BucketHandle
}

// offsetInfo is used to resume an interrupted iteration.
type offsetInfo struct {
	isBucketProcessed   bool
	lastProcessedObject string
}

// attributes contains metadata about the GCS source.
// This will be collected during the initial scan.
type attributes struct {
	numBuckets    uint32
	numObjects    uint64
	mu            sync.RWMutex
	bucketObjects map[string]uint64
}

func newStats(numBkts int) *attributes {
	return &attributes{
		numBuckets:    uint32(numBkts),
		bucketObjects: make(map[string]uint64, numBkts),
	}
}

func (s *attributes) incObjects() {
	s.mu.Lock()
	s.numObjects++
	s.mu.Unlock()
}

func (s *attributes) setBucketCnt(bkt string, cnt uint64) {
	s.mu.Lock()
	s.bucketObjects[bkt] = cnt
	s.mu.Unlock()
}

type gcsManagerOption func(*gcsManager) error

// withHTTPClient uses the provided HTTP client when creating a new GCS client.
func withHTTPClient(ctx context.Context, httpClient *http.Client) gcsManagerOption {
	client, err := storage.NewClient(ctx, option.WithHTTPClient(httpClient), option.WithScopes(storage.ScopeReadOnly))
	return func(m *gcsManager) error {
		if err != nil {
			return err
		}

		m.client = client
		return nil
	}
}

// withAPIKey uses the provided API key when creating a new GCS client.
// This can ONLY be used for public buckets.
func withAPIKey(ctx context.Context, apiKey string) gcsManagerOption {
	client, err := storage.NewClient(ctx, option.WithAPIKey(apiKey), option.WithScopes(storage.ScopeReadOnly))
	return func(m *gcsManager) error {
		if err != nil {
			return err
		}

		m.client = client
		return nil
	}
}

// withJSONServiceAccount uses the provided JSON service account when creating a new GCS client.
func withJSONServiceAccount(ctx context.Context, jsonServiceAccount []byte) gcsManagerOption {
	creds, err := google.CredentialsFromJSONWithType(ctx, jsonServiceAccount, google.ServiceAccount, storage.ScopeReadOnly)
	if err != nil {
		return func(m *gcsManager) error {
			return fmt.Errorf("failed to load credentials: %w", err)
		}
	}

	client, err := storage.NewClient(ctx, option.WithCredentials(creds))
	return func(m *gcsManager) error {
		if err != nil {
			return err
		}

		m.client = client
		return nil
	}
}

// withDefaultADC uses the default application credentials when creating a new GCS client.
func withDefaultADC(ctx context.Context) gcsManagerOption {
	client, err := defaultADC(ctx)
	return func(m *gcsManager) error {
		if err != nil {
			return err
		}

		m.client = client
		return nil
	}
}

// withoutAuthentication uses an unauthenticated client when creating a new GCS client.
// This can ONLY be used for public buckets.
func withoutAuthentication(ctx context.Context) gcsManagerOption {
	client, err := storage.NewClient(ctx, option.WithoutAuthentication(), option.WithScopes(storage.ScopeReadOnly))
	return func(m *gcsManager) error {
		if err != nil {
			return err
		}
		m.client = client
		m.withoutAuth = true
		return nil
	}
}

func defaultADC(ctx context.Context) (*storage.Client, error) {
	client, err := storage.NewClient(ctx, option.WithScopes(storage.ScopeReadOnly))
	if err != nil {
		return nil, err
	}
	return client, nil
}

// withIncludeBuckets sets the buckets that should be included in the scan.
// If used in conjunction with withExcludeBuckets, the include buckets will
// take precedence.
func withIncludeBuckets(buckets []string) gcsManagerOption {
	return func(m *gcsManager) error {
		if len(buckets) == 0 {
			return nil
		}
		if m.excludeBuckets != nil {
			m.excludeBuckets = nil
		}

		m.includeBuckets = make(map[string]struct{}, len(buckets))
		for _, bucket := range buckets {
			m.includeBuckets[bucket] = struct{}{}
		}
		return nil
	}
}

// withExcludeBuckets sets the buckets that should be excluded from the scan.
// If used in conjunction with withIncludeBuckets, the include buckets will
// take precedence.
func withExcludeBuckets(buckets []string) gcsManagerOption {
	return func(m *gcsManager) error {
		if len(buckets) == 0 {
			return nil
		}
		if m.includeBuckets != nil {
			return nil
		}

		m.excludeBuckets = make(map[string]struct{}, len(buckets))
		for _, bucket := range buckets {
			m.excludeBuckets[bucket] = struct{}{}
		}
		return nil
	}
}

// withIncludeObjects sets the objects that should be included in the scan.
// Using this option in conjuection with withIncludeBuckets will result in
// only specific buckets and objects being scanned.
// If the bucket(s) are known, it is recommended to also use withIncludeBuckets
// to increase the performance of the scan.
// If used in conjunction with any of the withExclude* or withIncludeBuckets options, this
// option will take precedence.
func withIncludeObjects(objects []string) gcsManagerOption {
	return func(m *gcsManager) error {
		if len(objects) == 0 {
			return nil
		}
		if m.excludeObjects != nil {
			m.excludeObjects = nil
		}

		m.includeObjects = make(map[string]struct{}, len(objects))
		for _, object := range objects {
			m.includeObjects[object] = struct{}{}
		}
		return nil
	}
}

// withExcludeObjects sets the objects that should be excluded from the scan.
// If used in conjunction with withIncludeObjects, the include objects will
// take precedence.
func withExcludeObjects(objects []string) gcsManagerOption {
	return func(m *gcsManager) error {
		if len(objects) == 0 {
			return nil
		}
		if m.includeObjects != nil {
			return nil
		}

		m.excludeObjects = make(map[string]struct{}, len(objects))
		for _, object := range objects {
			m.excludeObjects[object] = struct{}{}
		}
		return nil
	}
}

// withConcurrency sets the number of concurrent workers that will be used
// to process objects.
// If not set, or set to a negative number the default value is runtime.NumCPU().
func withConcurrency(concurrency int) gcsManagerOption {
	return func(m *gcsManager) error {
		if concurrency <= 0 {
			m.concurrency = defaultConcurrency
		} else {
			m.concurrency = concurrency
		}
		return nil
	}
}

// withMaxObjectSize sets the maximum size of objects that will be scanned.
// If not set, set to a negative number, or set larger than 1GB,
// the default value of 50MB will be used.
func withMaxObjectSize(maxObjectSize int64) gcsManagerOption {
	return func(m *gcsManager) error {
		if maxObjectSize <= 0 || maxObjectSize > maxObjectSizeLimit {
			m.maxObjectSize = defaultMaxObjectSize
		} else {
			m.maxObjectSize = maxObjectSize
		}

		return nil
	}
}

// withBucketOffsets sets the offset for each bucket.
// This is used to resume listing objects for a bucket.
func withBucketOffsets(offsets map[string]offsetInfo) gcsManagerOption {
	bkts := make(map[string]bucket, len(offsets))
	for bkt, offst := range offsets {
		bkts[bkt] = bucket{
			shouldInclude: !offst.isBucketProcessed,
			name:          bkt,
			startOffset:   offst.lastProcessedObject,
		}
	}
	return func(m *gcsManager) error {
		m.hasEnumerated = len(offsets) > 0 // offset means we are resuming.
		m.buckets = bkts
		return nil
	}
}

func newGCSManager(ctx context.Context, projectID string, opts ...gcsManagerOption) (*gcsManager, error) {
	// Default values for the manager.
	gcs := &gcsManager{
		projectID:     projectID,
		concurrency:   defaultConcurrency,
		maxObjectSize: defaultMaxObjectSize,
		buckets:       make(map[string]bucket),
	}

	for _, opt := range opts {
		if err := opt(gcs); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	if projectID == "" && !gcs.withoutAuth {
		return nil, fmt.Errorf("project ID is required, when using authentication")
	}

	// If no client was provided, use the default application credentials.
	// A client is required to perform any operations.
	if gcs.client == nil {
		c, err := defaultADC(ctx)
		if err != nil {
			return nil, err
		}
		gcs.client = c
	}
	configureWorkers(gcs)

	return gcs, nil
}

func configureWorkers(gcs *gcsManager) {
	gcs.workerPool = new(errgroup.Group)
	gcs.workerPool.SetLimit(gcs.concurrency)
}

// object is a representation of a GCS object.
type object struct {
	name        string
	bucket      string
	contentType string
	owner       string
	link        string
	md5         string
	// acl represents an ACLEntities.
	// https://pkg.go.dev/cloud.google.com/go/storage#ACLEntity
	acl       []string
	size      int64
	createdAt time.Time
	updatedAt time.Time

	io.Reader
}

func (g *gcsManager) Attributes(ctx context.Context) (*attributes, error) {
	// Get all the buckets in the project.
	buckets, err := g.listBuckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	return g.enumerate(ctx, buckets)
}

func (g *gcsManager) enumerate(ctx context.Context, bkts []bucket) (*attributes, error) {
	ctx = context.WithValues(ctx, "phase", "enumeration")

	ctx.Logger().V(1).Info("Enumerating buckets", "buckets", len(bkts))
	stats := newStats(len(bkts))

	defer func(start time.Time) {
		ctx.Logger().V(1).Info("Finished enumerating buckets", "buckets", len(bkts), "objects", stats.numObjects, "duration", time.Since(start))
	}(time.Now())

	for _, bkt := range bkts {
		g.workerPool.Go(func() error {
			bktCtx := context.WithValues(ctx, "bucket", bkt.name)
			// List all the objects in the bucket and calculate attributes.
			g.setupBktHandle(bktCtx, &bkt)

			q, err := setObjectQuery(&bkt)
			if err != nil {
				bktCtx.Logger().Error(err, "failed to set object query")
				return nil
			}

			var count uint64
			objs := bkt.Objects(bktCtx, q)
			for {
				obj, err := objs.Next()
				if errors.Is(err, iterator.Done) {
					bktCtx.Logger().V(2).Info("Enumerated bucket", "objects", count)
					break
				}
				if err != nil {
					if bktCtx.Err() == nil {
						bktCtx.Logger().Error(err, "Failed to list objects in bucket")
					}
					return nil
				}
				if obj == nil {
					bktCtx.Logger().V(5).Info("object is nil")
					continue
				}

				if !g.shouldIncludeObject(ctx, obj.Name) || g.shouldExcludeObject(ctx, obj.Name) {
					continue
				}
				count++
				stats.incObjects()
			}

			stats.setBucketCnt(bkt.name, count)
			return nil
		})
	}

	_ = g.workerPool.Wait()
	g.attr = stats

	return stats, nil
}

func (g *gcsManager) ListObjects(ctx context.Context) (chan io.Reader, error) {
	ch := make(chan io.Reader, 100) // TODO (ahrav): Determine optimal buffer size.

	// Get all the buckets in the project.
	buckets, err := g.listBuckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	// TODO (ahrav): This can be optimized if we set the buckets from within
	// the listBuckets method. This way seems a little more clear as to the intent.

	// Update the gcsManager with all the buckets to list objects from.
	// This is in addition to any buckets that were provided via the
	// withBucketOffsets option.
	for _, b := range buckets {
		g.buckets[b.name] = b
	}

	go func() {
		for _, bucket := range g.buckets {
			g.numBuckets++
			g.workerPool.Go(func() error {
				for obj := range g.listBucketObjects(ctx, &bucket) {
					ch <- obj
				}
				return nil
			})
		}

		_ = g.workerPool.Wait()
		close(ch)
	}()

	return ch, nil
}

func (g *gcsManager) listBuckets(ctx context.Context) ([]bucket, error) {
	var buckets []bucket
	if g.withoutAuth {
		for name := range g.includeBuckets {
			buckets = append(buckets, bucket{name: name})
		}
		ctx.Logger().V(1).Info("Using configured buckets, listing needs auth", "buckets", len(buckets))
		return buckets, nil
	}

	bkts := g.client.Buckets(ctx, g.projectID)
	for {
		bkt, err := bkts.Next()
		if errors.Is(err, iterator.Done) {
			ctx.Logger().V(1).Info("Listed buckets", "buckets", len(buckets))
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve bucket: %w", err)
		}

		// If the bucket is already in the map, skip it, it's already accounted for.
		// This is used to resume listing objects for a bucket.
		if _, ok := g.buckets[bkt.Name]; ok {
			ctx.Logger().V(4).Info("Skipping bucket", "bucket", bkt.Name, "reason", "already queued from saved progress")
			continue
		}
		if !g.shouldIncludeBucket(ctx, bkt.Name) || g.shouldExcludeBucket(ctx, bkt.Name) {
			ctx.Logger().V(4).Info("Skipping bucket", "bucket", bkt.Name, "reason", "matches filter")
			continue
		}
		buckets = append(buckets, bucket{name: bkt.Name})

	}
	return buckets, nil
}

// listBucketObjects streams the bucket's objects. A listing error is logged here,
// before the channel closes, so the caller can't miss it.
func (g *gcsManager) listBucketObjects(ctx context.Context, bkt *bucket) chan io.Reader {
	ch := make(chan io.Reader, 100)

	go func() {
		defer close(ch)

		ctx := context.WithValues(ctx, "bucket", bkt.name)
		ctx.Logger().V(2).Info("Listing objects in bucket", "start_offset", bkt.startOffset)

		g.setupBktHandle(ctx, bkt)

		// TODO (ahrav): Look to extend gcsManager to allow for exact buckets/objects
		// include filters. This will increase performance substantially

		if err := g.bucketObjects(ctx, bkt, ch); err != nil && ctx.Err() == nil {
			ctx.Logger().Error(err, "Failed to list bucket objects")
		}
	}()
	return ch
}

func (g *gcsManager) setupBktHandle(ctx context.Context, bkt *bucket) {
	b := g.client.Bucket(bkt.name).Retryer(
		storage.WithBackoff(gax.Backoff{
			Initial:    2 * time.Second,
			Max:        30 * time.Second,
			Multiplier: 1.5,
		}),
		storage.WithPolicy(storage.RetryAlways),
		storage.WithErrorFunc(func(err error) bool {
			retry := storage.ShouldRetry(err)
			if retry {
				ctx.Logger().V(4).Info("Retrying GCS request", "error", retryError(err))
			}
			return retry
		}),
	)
	bkt.BucketHandle = b
}

// retryError returns the error text without the request URL, since an API key is
// sent in the URL query.
func retryError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err.Error()
	}
	return err.Error()
}

func (g *gcsManager) bucketObjects(ctx context.Context, bkt *bucket, ch chan<- io.Reader) error {
	q, err := setObjectQuery(bkt)
	if err != nil {
		return fmt.Errorf("failed to set object query: %w", err)
	}

	var listed, skipped int
	objs := bkt.Objects(ctx, q)
	for {
		obj, err := objs.Next()
		if errors.Is(err, iterator.Done) {
			ctx.Logger().V(2).Info("Finished listing objects in bucket", "objects", listed, "skipped", skipped)
			break
		}
		if err != nil {
			return fmt.Errorf("failed to retrieve object iterator: %w", err)
		}
		if obj == nil {
			ctx.Logger().V(5).Info("object is nil")
			continue
		}

		objCtx := context.WithValues(ctx, "object", obj.Name)
		if !g.shouldIncludeObject(ctx, obj.Name) || g.shouldExcludeObject(ctx, obj.Name) {
			objCtx.Logger().V(4).Info("Skipping object", "reason", "matches filter")
			skipped++
			continue
		}

		o, err := g.constructObject(objCtx, bkt.Object(obj.Name))
		if errors.Is(err, errObjectSkipped) {
			skipped++
			continue
		}
		if err != nil {
			if objCtx.Err() == nil {
				objCtx.Logger().Error(err, "Failed to read object")
			}
			continue
		}
		listed++
		ch <- o
	}
	return nil
}

func setObjectQuery(bkt *bucket) (*storage.Query, error) {
	// Setting the attribute selection is a performance optimization.
	// https://pkg.go.dev/cloud.google.com/go/storage#Query.SetAttrSelection
	q := new(storage.Query)
	err := q.SetAttrSelection([]string{
		"Name",
		"ContentType",
		"Owner",
		"Size",
		"Updated",
		"Created",
		"ACL",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set attribute selection: %w", err)
	}

	// If a start offset is provided, then we need to set it on the query.
	// This will begin listing objects from the start offset.
	if bkt.startOffset != "" {
		q.StartOffset = bkt.startOffset
	}
	return q, nil
}

func (g *gcsManager) constructObject(ctx context.Context, obj *storage.ObjectHandle) (object, error) {
	o := object{}
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		return o, fmt.Errorf("failed to retrieve object attributes: %w", err)
	}

	if !isObjectTypeValid(ctx, attrs.Name) || !g.isObjectSizeValid(ctx, attrs.Size) {
		return o, errObjectSkipped
	}

	rc, err := obj.NewReader(ctx)
	if err != nil {
		return o, fmt.Errorf("failed to retrieve object reader: %w", err)
	}

	o.name = attrs.Name
	o.bucket = attrs.Bucket
	o.contentType = attrs.ContentType
	o.owner = attrs.Owner
	o.link = attrs.MediaLink
	o.md5 = hex.EncodeToString(attrs.MD5)
	o.createdAt = attrs.Created
	o.updatedAt = attrs.Updated
	o.acl = objectACLs(attrs.ACL)
	o.size = attrs.Size
	o.Reader = rc

	atomic.AddUint64(&g.numObjects, 1)

	return o, nil
}

func objectACLs(acl []storage.ACLRule) []string {
	acls := make([]string, 0, len(acl))
	for _, rule := range acl {
		acls = append(acls, string(rule.Entity))
	}
	return acls
}

func isObjectTypeValid(ctx context.Context, name string) bool {
	isValid := !common.SkipFile(name)
	if !isValid {
		ctx.Logger().V(4).Info("Skipping object", "reason", "file type is skipped")
		return false
	}
	return true
}

func (g *gcsManager) isObjectSizeValid(ctx context.Context, size int64) bool {
	isValid := size > 0 && size <= g.maxObjectSize
	if !isValid {
		ctx.Logger().V(4).Info("Skipping object", "reason", "size out of range", "size", size, "max_size", g.maxObjectSize)
		return false
	}
	return true
}

func (g *gcsManager) shouldIncludeBucket(ctx context.Context, bkt string) bool {
	if len(g.includeBuckets) == 0 {
		return true
	}
	return shouldProcess(ctx, bkt, g.includeBuckets, globMatches)
}

func (g *gcsManager) shouldExcludeBucket(ctx context.Context, bkt string) bool {
	return shouldProcess(ctx, bkt, g.excludeBuckets, globMatches)
}

func (g *gcsManager) shouldIncludeObject(ctx context.Context, obj string) bool {
	if len(g.includeObjects) == 0 {
		return true
	}
	return shouldProcess(ctx, obj, g.includeObjects, globMatches)
}

func (g *gcsManager) shouldExcludeObject(ctx context.Context, obj string) bool {
	return shouldProcess(ctx, obj, g.excludeObjects, globMatches)
}

type globMatcherFn func(string, glob.Glob) bool

func shouldProcess(ctx context.Context, s string, matchers map[string]struct{}, matcherFn globMatcherFn) bool {
	if len(matchers) == 0 {
		return false
	}

	for m := range matchers {
		g, err := glob.Compile(m)
		if err != nil {
			ctx.Logger().V(1).Info("failed to compile glob", "glob", m, "error", err)
			continue
		}

		if matcherFn(s, g) {
			return true
		}
	}
	return false
}

func globMatches(s string, g glob.Glob) bool {
	return g.Match(s)
}
