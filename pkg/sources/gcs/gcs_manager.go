package gcs

import (
	aCtx "context"
	"fmt"
	"io"
	"runtime"
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
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	defaultMaxObjectSize = 500 * 1024 * 1024      // 500MB
	maxObjectSizeLimit   = 1 * 1024 * 1024 * 1024 // 1GB
)

var (
	defaultConcurrency = runtime.NumCPU()
)

type objectManager interface {
	listObjects(context.Context) (chan io.Reader, error)
}

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

	concurrency int
	workerPool  *errgroup.Group

	maxObjectSize int64
	numBuckets    uint32
	numObjects    uint64

	includeBuckets,
	excludeBuckets,
	includeObjects,
	excludeObjects map[string]struct{}
	client bucketManager
}

type gcsManagerOption func(*gcsManager) error

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
	client, err := storage.NewClient(ctx, option.WithCredentialsJSON(jsonServiceAccount), option.WithScopes(storage.ScopeReadOnly))
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
	return func(m *gcsManager) error {
		client, err := defaultADC(ctx)
		if err != nil {
			return err
		}

		m.client = client
		return nil
	}
}

// withoutAuthentication uses an unauthenticated client when creating a new GCS client.
// This can ONLY be used for public buckets.
func withoutAuthentication() gcsManagerOption {
	client, err := storage.NewClient(aCtx.Background(), option.WithoutAuthentication(), option.WithScopes(storage.ScopeReadOnly))
	return func(m *gcsManager) error {
		if err != nil {
			return err
		}
		m.client = client
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
// the default value of 500MB will be used.
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

func newGCSManager(projectID string, opts ...gcsManagerOption) (*gcsManager, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}

	gcs := &gcsManager{
		projectID:     projectID,
		concurrency:   defaultConcurrency,
		maxObjectSize: defaultMaxObjectSize,
	}

	for _, opt := range opts {
		if err := opt(gcs); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// If no client was provided, use the default application credentials.
	// A client is required to perform any operations.
	if gcs.client == nil {
		c, err := defaultADC(context.Background())
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
	// acl represents an ACLEntities.
	// https://pkg.go.dev/cloud.google.com/go/storage#ACLEntity
	acl       []string
	size      int64
	createdAt time.Time
	updatedAt time.Time

	io.Reader
}

func (g *gcsManager) listObjects(ctx context.Context) (chan io.Reader, error) {
	ch := make(chan io.Reader, 100) // TODO (ahrav): Determine optimal buffer size.

	// Get all the buckets in the project.
	bucketNames, err := g.listBuckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}

	gcsErrs := sources.NewScanErrors()

	for _, bucket := range bucketNames {
		g.numBuckets++
		bucket := bucket
		g.workerPool.Go(func() error {
			objCh, errCh := g.listBucketObjects(ctx, bucket)
			for {
				select {
				case obj, ok := <-objCh:
					if !ok {
						return nil
					}
					ch <- obj
				case err := <-errCh:
					gcsErrs.Add(err)
					return nil
				}
			}
		})
	}

	go func() {
		_ = g.workerPool.Wait()
		if gcsErrs.Count() > 0 {
			ctx.Logger().V(2).Info("encountered gcsErrs while scanning GCS buckets", "error-count", gcsErrs.Count(), "gcsErrs", gcsErrs.String())
		}
		close(ch)
	}()

	return ch, nil
}

func (g *gcsManager) listBuckets(ctx context.Context) ([]string, error) {
	var bucketNames []string

	bkts := g.client.Buckets(ctx, g.projectID)
	for {
		bkt, err := bkts.Next()
		if errors.Is(err, iterator.Done) {
			ctx.Logger().V(5).Info("finished listing buckets", "num_buckets", len(bucketNames))
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve bucket: %w", err)
		}

		if !g.shouldIncludeBucket(ctx, bkt.Name) || g.shouldExcludeBucket(ctx, bkt.Name) {
			continue
		}

		bucketNames = append(bucketNames, bkt.Name)
	}

	return bucketNames, nil
}

func (g *gcsManager) listBucketObjects(ctx context.Context, bktName string) (chan io.Reader, chan error) {
	ch := make(chan io.Reader, 100)
	errCh := make(chan error, 1)

	go func() {
		defer close(ch)

		logger := ctx.Logger().WithValues("bucket", bktName)
		logger.V(5).Info("listing object(s) in bucket")

		bkt := g.client.Bucket(bktName).Retryer(
			storage.WithBackoff(gax.Backoff{
				Initial:    2 * time.Second,
				Max:        30 * time.Second,
				Multiplier: 1.5,
			}),
			storage.WithPolicy(storage.RetryAlways),
		)
		// TODO (ahrav): Look to extend gcsManager to allow for exact buckets/objects
		// in include/filters. This will increae performance substantially
		// If include objects are indicated, then we only need to scan for the
		// objects that are in the include bucket.
		// This is an optimization to avoid scanning the entire bucket.
		// if len(g.includeObjects) > 0 {
		// 	g.includeBucketObjects(ctx, bkt, ch)
		// 	return
		// }

		if err := g.bucketObjects(ctx, bkt, ch); err != nil {
			errCh <- fmt.Errorf("failed to list bucket objects: %w", err)
		}
	}()

	return ch, errCh
}

func (g *gcsManager) bucketObjects(ctx context.Context, bkt *storage.BucketHandle, ch chan<- io.Reader) error {
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
		return fmt.Errorf("failed to set attribute selection: %w", err)
	}

	objs := bkt.Objects(ctx, nil)
	for {
		obj, err := objs.Next()
		if errors.Is(err, iterator.Done) {
			ctx.Logger().V(5).Info("finished listing objects in bucket")
			break
		}
		if !g.shouldIncludeObject(ctx, obj.Name) || g.shouldExcludeObject(ctx, obj.Name) {
			continue
		}

		if err != nil {
			return fmt.Errorf("failed to retrieve iterator: %w", err)
		}

		o, err := g.constructObject(ctx, bkt.Object(obj.Name))
		if err != nil {
			ctx.Logger().V(1).Info("failed to create object", "object-name", obj.Name, "error", err)
			continue
		}
		ch <- o
	}

	return nil
}

func (g *gcsManager) constructObject(ctx context.Context, obj *storage.ObjectHandle) (object, error) {
	o := object{}
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		return o, fmt.Errorf("failed to retrieve object attributes: %w", err)
	}

	if !isObjectTypeValid(ctx, attrs.Name) || !g.isObjectSizeValid(ctx, attrs.Size) {
		return o, fmt.Errorf("object is not valid")
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
	o.createdAt = attrs.Created
	o.updatedAt = attrs.Updated
	o.acl = objectACLs(attrs.ACL)
	o.size = attrs.Size
	o.Reader = rc

	atomic.AddUint64(&g.numObjects, 1)

	return o, nil
}

func isObjectTypeValid(ctx context.Context, name string) bool {
	isValid := !common.SkipFile(name)
	if !isValid {
		ctx.Logger().V(2).Info("object type is invalid", "object-name", name)
		return false
	}
	return true
}

func (g *gcsManager) isObjectSizeValid(ctx context.Context, size int64) bool {
	isValid := size > 0 && size <= g.maxObjectSize
	if !isValid {
		ctx.Logger().V(2).Info("object size is invalid", "object-size", size)
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

func objectACLs(acl []storage.ACLRule) []string {
	acls := make([]string, 0, len(acl))
	for _, rule := range acl {
		acls = append(acls, string(rule.Entity))
	}
	return acls
}
