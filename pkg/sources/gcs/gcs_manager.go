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
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var defaultConcurrency = runtime.NumCPU()

// object is a representation of a GCS object.
type object struct {
	name        string
	bucket      string
	contentType string
	owner       string
	// acl represents an ACLEntities.
	// https://pkg.go.dev/cloud.google.com/go/storage#ACLEntity
	acl       []string
	size      int64
	createdAt time.Time
	updatedAt time.Time

	reader io.Reader
}

type objectManager interface {
	listObjects(context.Context) (chan object, error)
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

	// resumeFrom is the name of the last object that was processed.
	// This works because GCS returns objects in lexicographical order.
	resumeFrom  string
	concurrency int
	workerPool  *errgroup.Group

	numBuckets uint32
	numObjects uint64

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

func newGCSManager(projectID string, opts ...gcsManagerOption) (*gcsManager, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}

	gcs := &gcsManager{
		projectID:   projectID,
		concurrency: defaultConcurrency,
	}

	for _, opt := range opts {
		if err := opt(gcs); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	configureWorkers(gcs)

	return gcs, nil
}

func configureWorkers(gcs *gcsManager) {
	gcs.workerPool = new(errgroup.Group)
	gcs.workerPool.SetLimit(gcs.concurrency)
}

func (g *gcsManager) listObjects(ctx context.Context) (chan object, error) {
	ch := make(chan object, 100) // TODO (ahrav): Determine optimal buffer size.

	var (
		bucketNames []string
		err         error
	)
	if len(g.includeBuckets) > 0 {
		// Handle include buckets.
		for bucket := range g.includeBuckets {
			bucketNames = append(bucketNames, bucket)
		}
	} else {
		// Get all the buckets in the project.
		if bucketNames, err = g.listBuckets(ctx); err != nil {
			return nil, fmt.Errorf("failed to list buckets: %w", err)
		}
	}

	for _, bucket := range bucketNames {
		g.numBuckets++
		bucket := bucket
		g.workerPool.Go(func() error {
			for obj := range g.listBucketObjects(ctx, bucket) {
				ch <- obj
			}
			return nil
		})
	}

	go func() {
		_ = g.workerPool.Wait()
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
			break
		}
		if g.shouldExcludeBucket(ctx, bkt.Name) {
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("failed to retrieve bucket: %w", err)
		}
		bucketNames = append(bucketNames, bkt.Name)
	}

	return bucketNames, nil
}

func (g *gcsManager) shouldExcludeBucket(ctx context.Context, bkt string) bool {
	for bucket := range g.excludeBuckets {
		g, err := glob.Compile(bucket)
		if err != nil {
			ctx.Logger().V(1).Info("failed to compile glob", "glob", bucket, "error", err)
			continue
		}

		if g.Match(bkt) {
			ctx.Logger().V(3).Info("skipping bucket", "bucket", bkt, "glob", bucket)
			return true
		}
	}
	return false
}

func (g *gcsManager) listBucketObjects(ctx context.Context, bktName string) <-chan object {
	ch := make(chan object, 100)

	go func() {
		defer close(ch)

		logger := ctx.Logger().WithValues("bucket", bktName)
		logger.V(5).Info("listing object(s) in bucket")

		bkt := g.client.Bucket(bktName)
		// If include objects are includes and the bucket is in the include
		// buckets, then we only need to scan for the objects that are in the
		// include bucket.
		if _, ok := g.includeBuckets[bktName]; ok && len(g.includeObjects) > 0 {
			g.includeBucketObjects(ctx, bkt, ch)
			return
		}

		g.bucketObjects(ctx, bkt, ch)
	}()

	return ch
}

func (g *gcsManager) includeBucketObjects(ctx context.Context, bkt *storage.BucketHandle, ch chan object) {
	for o := range g.includeObjects {
		obj := bkt.Object(o)

		o, err := g.constructObject(ctx, obj)
		if err != nil {
			ctx.Logger().V(1).Info("failed to create object", "object-name", o, "error", err)
			continue
		}
		ch <- *o
	}
}

func (g *gcsManager) bucketObjects(ctx context.Context, bkt *storage.BucketHandle, ch chan object) {
	objs := bkt.Objects(ctx, nil)
	for {
		obj, err := objs.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if g.shouldExcludeObject(ctx, obj.Name) {
			continue
		}

		if err != nil {
			ctx.Logger().Error(err, "failed to get iterator object")
			return
		}

		o, err := g.constructObject(ctx, bkt.Object(obj.Name))
		if err != nil {
			ctx.Logger().V(1).Info("failed to create object", "object-name", obj.Name, "error", err)
			continue
		}
		ch <- *o
	}
}

func (g *gcsManager) constructObject(ctx context.Context, obj *storage.ObjectHandle) (*object, error) {
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve object attributes: %w", err)
	}

	atomic.AddUint64(&g.numObjects, 1)
	rc, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve object reader: %w", err)
	}

	object := object{
		name:        attrs.Name,
		bucket:      attrs.Bucket,
		contentType: attrs.ContentType,
		owner:       attrs.Owner,
		createdAt:   attrs.Created,
		updatedAt:   attrs.Updated,
		acl:         objectACLs(attrs.ACL),
		size:        attrs.Size,
	}
	object.reader = rc

	return &object, nil
}

func (g *gcsManager) shouldExcludeObject(ctx context.Context, obj string) bool {
	for object := range g.excludeObjects {
		g, err := glob.Compile(object)
		if err != nil {
			ctx.Logger().V(1).Info("failed to compile glob", "glob", object, "error", err)
			continue
		}

		if g.Match(obj) {
			ctx.Logger().V(3).Info("skipping object", "object", obj, "glob", object)
			return true
		}
	}
	return false
}

func objectACLs(acl []storage.ACLRule) []string {
	acls := make([]string, 0, len(acl))
	for _, rule := range acl {
		acls = append(acls, string(rule.Entity))
	}
	return acls
}
