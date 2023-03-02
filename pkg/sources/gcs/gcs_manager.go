package gcs

import (
	"fmt"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type object struct{}

type objectManager interface {
	listObjects(context.Context) (chan<- *object, error)
}

// gcsManager serves as simple facade for interacting with GCS.
// It's main purpose is to retrieve objects from GCS.
type gcsManager struct {
	projectID string

	// resumeFrom is the name of the last object that was processed.
	// This works because GCS returns objects in lexicographical order.
	resumeFrom string

	includeBuckets,
	excludeBuckets,
	includeObjects,
	excludeObjects map[string]struct{}
	client *storage.Client
}

func (g *gcsManager) listObjects(ctx context.Context) (chan<- *object, error) {
	ch := make(chan<- *object)
	return ch, nil
}

type gcsManagerOption func(*gcsManager) error

// withAPIKey uses the provided API key when creating a new GCS client.
func withAPIKey(ctx context.Context, apiKey string) gcsManagerOption {
	client, err := storage.NewClient(ctx, option.WithAPIKey(apiKey))

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
// If used in conjunction with withExcludeObjects, the include objects will
// take precedence.
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

func newGCSManager(projectID string, opts ...gcsManagerOption) (*gcsManager, error) {
	if projectID == "" {
		return nil, fmt.Errorf("project ID is required")
	}

	gcs := &gcsManager{
		projectID: projectID,
	}

	for _, opt := range opts {
		opt(gcs)
	}

	return gcs, nil
}
