package s3

import (
	"testing"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSource_CountsTowardProgress(t *testing.T) {
	filter, err := newObjectFilter(nil, []string{"archive/"}, nil, nil)
	require.NoError(t, err)
	s := Source{maxObjectSize: 1024, objectFilter: filter}

	key, filteredKey := "keep/obj.txt", "archive/obj.txt"
	size, oversize := int64(512), int64(2048)

	tests := []struct {
		name string
		obj  s3types.Object
		want bool
	}{
		{name: "standard object", obj: s3types.Object{Key: &key, Size: &size}, want: true},
		{name: "at the size limit", obj: s3types.Object{Key: &key, Size: &s.maxObjectSize}, want: true},
		{name: "over the size limit", obj: s3types.Object{Key: &key, Size: &oversize}, want: false},
		{
			name: "glacier",
			obj:  s3types.Object{Key: &key, Size: &size, StorageClass: s3types.ObjectStorageClassGlacier},
			want: false,
		},
		{
			name: "glacier instant retrieval",
			obj:  s3types.Object{Key: &key, Size: &size, StorageClass: s3types.ObjectStorageClassGlacierIr},
			want: false,
		},
		// pageChunker counts a filtered object as done before it looks at storage class or size, so the
		// total has to include it too.
		{name: "filtered", obj: s3types.Object{Key: &filteredKey, Size: &size}, want: true},
		{
			name: "filtered and over the size limit",
			obj:  s3types.Object{Key: &filteredKey, Size: &oversize},
			want: true,
		},
		{
			name: "filtered and glacier",
			obj:  s3types.Object{Key: &filteredKey, Size: &size, StorageClass: s3types.ObjectStorageClassGlacier},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, s.countsTowardProgress(tt.obj))
		})
	}
}

func TestScanProgress_Percent(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(p *scanProgress)
		wantValue int64
	}{
		{
			name:      "nothing counted",
			setup:     func(p *scanProgress) {},
			wantValue: 0,
		},
		{
			name: "listing in flight",
			setup: func(p *scanProgress) {
				p.listingsInFlight.Add(1)
				p.addTotal(10, 1000)
				p.addDone(5, 500)
			},
			wantValue: 0,
		},
		{
			name: "count failed",
			setup: func(p *scanProgress) {
				p.countFailed.Store(true)
				p.addTotal(10, 1000)
				p.addDone(5, 500)
			},
			wantValue: 0,
		},
		{
			name: "partial rounds down",
			setup: func(p *scanProgress) {
				p.addTotal(3, 3000)
				p.addDone(1, 1999)
			},
			wantValue: 66,
		},
		{
			name: "all done caps at 99",
			setup: func(p *scanProgress) {
				p.addTotal(10, 1000)
				p.addDone(10, 1000)
			},
			wantValue: 99,
		},
		{
			name: "done exceeds total caps at 99",
			setup: func(p *scanProgress) {
				p.addTotal(10, 1000)
				p.addDone(12, 1200)
			},
			wantValue: 99,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p scanProgress
			tt.setup(&p)
			assert.Equal(t, tt.wantValue, p.percent())
		})
	}
}

func TestSource_PublishProgressAfterCountPass(t *testing.T) {
	s := Source{objectProgress: &scanProgress{}}
	s.objectProgress.listingsInFlight.Add(1)
	s.objectProgress.addTotal(4, 4000)
	s.objectProgress.addDone(2, 2000)

	// A publish while the count is still running cannot know the total yet.
	s.publishProgress()
	assert.Zero(t, s.GetProgress().PercentComplete)

	// The count pass publishes once it has finished, so the bar does not wait for the next object.
	s.objectProgress.listingsInFlight.Add(-1)
	s.publishProgress()
	assert.EqualValues(t, 50, s.GetProgress().PercentComplete)
}
