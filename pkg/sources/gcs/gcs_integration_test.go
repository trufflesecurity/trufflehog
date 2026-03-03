//go:build integration
// +build integration

package gcs

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestChunks(t *testing.T) {
	ctx := context.Background()

	source, conn := createTestSource(&sourcespb.GCS{
		ProjectId:      testProjectID,
		Credential:     &sourcespb.GCS_Adc{},
		ExcludeBuckets: []string{perfTestBucketGlob, publicBucket},
	})

	err := source.Init(ctx, "test", 1, 1, true, conn, 8)
	assert.Nil(t, err)

	chunksCh := make(chan *sources.Chunk, 1)

	go func() {
		defer close(chunksCh)
		err := source.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	want := createTestChunks()

	got := make([]*sources.Chunk, 0, len(want))
	for chunk := range chunksCh {
		got = append(got, chunk)
	}
	sort.Slice(got, func(i, j int) bool {
		return got[i].SourceMetadata.GetGcs().Filename < got[j].SourceMetadata.GetGcs().Filename
	})

	assert.Equal(t, len(want), len(got))

	for i, chunk := range got {
		if diff := cmp.Diff(want[i].SourceMetadata.GetGcs(), chunk.SourceMetadata.GetGcs(),
			cmpopts.IgnoreFields(source_metadatapb.GCS{}, "state", "sizeCache", "unknownFields", "CreatedAt", "UpdatedAt"),
		); diff != "" {
			t.Errorf("chunk mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestChunks_PublicBucket(t *testing.T) {
	ctx := context.Background()

	source, conn := createTestSource(&sourcespb.GCS{
		Credential:     &sourcespb.GCS_Unauthenticated{},
		IncludeBuckets: []string{publicBucket},
	})

	err := source.Init(ctx, "test", 1, 1, true, conn, 8)
	assert.Nil(t, err)

	chunksCh := make(chan *sources.Chunk, 1)

	go func() {
		defer close(chunksCh)
		err := source.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	want := []*sources.Chunk{
		{
			SourceName:   "test",
			SourceType:   sourcespb.SourceType_SOURCE_TYPE_GCS,
			SourceID:     0,
			SourceVerify: true,
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gcs{
					Gcs: &source_metadatapb.GCS{
						Filename:    "aws1.txt",
						Bucket:      publicBucket,
						ContentType: "text/plain",
						Email:       "",
						Link:        "https://storage.googleapis.com/download/storage/v1/b/public-trufflehog-test-bucket/o/aws1.txt?generation=1678334408999764&alt=media",
						Acls:        []string{},
					},
				},
			},
		},
	}

	got := make([]*sources.Chunk, 0, len(want))
	for chunk := range chunksCh {
		got = append(got, chunk)
	}
	sort.Slice(got, func(i, j int) bool {
		return got[i].SourceMetadata.GetGcs().Filename < got[j].SourceMetadata.GetGcs().Filename
	})

	assert.Equal(t, len(want), len(got))

	for i, chunk := range got {
		if diff := cmp.Diff(want[i].SourceMetadata.GetGcs(), chunk.SourceMetadata.GetGcs(),
			cmpopts.IgnoreFields(source_metadatapb.GCS{}, "state", "sizeCache", "unknownFields", "CreatedAt", "UpdatedAt"),
		); diff != "" {
			t.Errorf("chunk mismatch (-want +got):\n%s", diff)
		}
	}
}

func createTestChunks() []*sources.Chunk {
	objects := []object{
		{
			name:        "aws1.txt",
			bucket:      testBucket,
			contentType: "text/plain",
			size:        150,
			link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/aws1.txt?generation=1677870994890594&alt=media",
			acl:         []string{},
		},
		{
			name:        "moar2.txt",
			bucket:      testBucket,
			contentType: "text/plain",
			size:        12,
			link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th/o/moar2.txt?generation=1677871000378542&alt=media",
			acl:         []string{},
		},
		{
			name:        "aws3.txt",
			bucket:      testBucket2,
			contentType: "text/plain",
			size:        150,
			link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th2/o/aws3.txt?generation=1677871022489611&alt=media",
			acl:         []string{},
		},
		{
			name:        "moar.txt",
			bucket:      testBucket3,
			contentType: "text/plain",
			size:        6,
			link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th3/o/moar.txt?generation=1677871042896804&alt=media",
			acl:         []string{},
		},
		{
			name:        "AMAZON_FASHION_5.json",
			bucket:      testBucket4,
			contentType: "application/json",
			size:        1413469,
			link:        "https://storage.googleapis.com/download/storage/v1/b/test-bkt-th4/o/AMAZON_FASHION_5.json?generation=1677871063457469&alt=media",
			acl:         []string{},
		},
	}

	chunks := make([]*sources.Chunk, 0, len(objects))
	for _, o := range objects {
		chunks = append(chunks, &sources.Chunk{
			SourceName:   "test",
			SourceType:   sourcespb.SourceType_SOURCE_TYPE_GCS,
			SourceID:     0,
			SourceVerify: true,
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gcs{
					Gcs: &source_metadatapb.GCS{
						Filename:    o.name,
						Bucket:      o.bucket,
						ContentType: o.contentType,
						Email:       o.owner,
						Link:        o.link,
						Acls:        o.acl,
					},
				},
			},
		})
	}
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].SourceMetadata.GetGcs().Filename < chunks[j].SourceMetadata.GetGcs().Filename
	})

	return chunks
}
