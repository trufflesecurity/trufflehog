package gcs

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	testProjectID = "test-project"
	testAPIKey    = "test-api-key"
)

func TestNewGcsManager(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name    string
		projID  string
		opts    []gcsManagerOption
		want    *gcsManager
		wantErr bool
	}{
		{
			name:   "new gcs manager, no options",
			projID: testProjectID,
			want:   &gcsManager{projectID: testProjectID},
		},
		{
			name:    "new gcs manager, no project id",
			projID:  "",
			wantErr: true,
		},
		{
			name:   "new gcs manager, with api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withAPIKey(ctx, testAPIKey)},
			want:   &gcsManager{projectID: testProjectID},
		},
		{
			name:   "new gcs manager, with include buckets",
			projID: testProjectID,
			opts:   []gcsManagerOption{withIncludeBuckets([]string{"bucket1", "bucket2"})},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{"bucket1": {}, "bucket2": {}},
			},
		},
		{
			name:   "new gcs manager, with include buckets and api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withIncludeBuckets([]string{"bucket1", "bucket2"}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{"bucket1": {}, "bucket2": {}},
			},
		},
		{
			name:   "new gcs manager, with exclude buckets",
			projID: testProjectID,
			opts:   []gcsManagerOption{withExcludeBuckets([]string{"bucket1", "bucket2"})},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeBuckets: map[string]struct{}{"bucket1": {}, "bucket2": {}},
			},
		},
		{
			name:   "new gcs manager, with exclude buckets and api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withExcludeBuckets([]string{"bucket1", "bucket2"}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeBuckets: map[string]struct{}{"bucket1": {}, "bucket2": {}},
			},
		},
		{
			name:   "new gcs manager, with include and exclude buckets",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withIncludeBuckets([]string{"bucket1", "bucket2"}),
				withExcludeBuckets([]string{"bucket3", "bucket4"}),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{"bucket1": {}, "bucket2": {}},
			},
		},
		{
			name:   "new gcs manager, with include and exclude buckets and api key",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withIncludeBuckets([]string{"bucket1", "bucket2"}),
				withExcludeBuckets([]string{"bucket3", "bucket4"}),
				withAPIKey(ctx, testAPIKey),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{"bucket1": {}, "bucket2": {}},
			},
		},
		{
			name:   "new gcs manager, with include objects",
			projID: testProjectID,
			opts:   []gcsManagerOption{withIncludeObjects([]string{"object1", "object2"})},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{"object1": {}, "object2": {}},
			},
		},
		{
			name:   "new gcs manager, with include objects and api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withIncludeObjects([]string{"object1", "object2"}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{"object1": {}, "object2": {}},
			},
		},
		{
			name:   "new gcs manager, with exclude objects",
			projID: testProjectID,
			opts:   []gcsManagerOption{withExcludeObjects([]string{"object1", "object2"})},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeObjects: map[string]struct{}{"object1": {}, "object2": {}},
			},
		},
		{
			name:   "new gcs manager, with exclude objects and api key",
			projID: testProjectID,
			opts:   []gcsManagerOption{withExcludeObjects([]string{"object1", "object2"}), withAPIKey(ctx, testAPIKey)},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeObjects: map[string]struct{}{"object1": {}, "object2": {}},
			},
		},
		{
			name:   "new gcs manager, with include and exclude objects",
			projID: testProjectID,
			opts: []gcsManagerOption{
				withIncludeObjects([]string{"object1", "object2"}),
				withExcludeObjects([]string{"object3", "object4"}),
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{"object1": {}, "object2": {}},
			},
		},
		{
			name:   "new gcs manager, with concurrency",
			projID: testProjectID,
			opts:   []gcsManagerOption{withConcurrency(10)},
			want: &gcsManager{
				projectID:   testProjectID,
				concurrency: 10,
			},
		},
		{
			name:   "new gcs manager, default concurrency",
			projID: testProjectID,
			want: &gcsManager{
				projectID:   testProjectID,
				concurrency: defaultConcurrency,
			},
		},
		{
			name:   "new gcs manager, with negative concurrency",
			projID: testProjectID,
			opts:   []gcsManagerOption{withConcurrency(-1)},
			want: &gcsManager{
				projectID:   testProjectID,
				concurrency: defaultConcurrency,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newGCSManager(tc.projID, tc.opts...)
			if (err != nil) != tc.wantErr {
				t.Errorf("newGCSManager() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !cmp.Equal(got, tc.want, cmp.AllowUnexported(gcsManager{}), cmpopts.IgnoreFields(gcsManager{}, "client")) {
				t.Errorf("newGCSManager(%v, %v) got: %v, %v, want: %v, %v", tc.projID, tc.opts, got, err, tc.want, nil)
			}
		})
	}
}
