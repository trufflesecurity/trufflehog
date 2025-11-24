//go:build integration
// +build integration

package s3

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_ChunksCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	s := Source{}
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Buckets:    []string{"truffletestbucket"},
	}
	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "test name", 0, 0, false, conn, 1)
	chunksCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunksCh)
		err = s.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	wantChunkCount := 102
	got := 0

	for range chunksCh {
		got++
	}
	assert.Greater(t, got, wantChunkCount)
}

func TestSource_ChunksLarge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	s := Source{}
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Buckets:    []string{"trufflesec-ahrav-test"},
	}
	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "test name", 0, 0, false, conn, 1)
	chunksCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunksCh)
		err = s.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	wantChunkCount := 9637
	got := 0

	for range chunksCh {
		got++
	}
	assert.Equal(t, got, wantChunkCount)
}

func TestSource_Validate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	tests := []struct {
		name          string
		roles         []string
		buckets       []string
		ignoreBuckets []string
		wantErrCount  int
	}{
		{
			name: "buckets without roles, can access all buckets",
			buckets: []string{
				"truffletestbucket-s3-tests",
			},
			wantErrCount: 0,
		},
		{
			name: "buckets without roles, one error per inaccessible bucket",
			buckets: []string{
				"truffletestbucket-s3-tests",
				"truffletestbucket-s3-role-assumption",
				"truffletestbucket-no-access",
			},
			wantErrCount: 2,
		},
		{
			// As of the time of this writing the account has six inaccessible buckets. If that is changed, this test
			// will break. This test was written to balance between speed of implementation and robustness.
			name: "ignored buckets, one error per inaccessible bucket",
			ignoreBuckets: []string{
				"trufflebucketforall",
				"truffletestbucket-no-access",
				"truffletestbucket-roleassumption",
				"truffletestbucket-s3-role-assumption",
			},
			wantErrCount: 2,
		},
		{
			name: "roles without buckets, all can access at least one account bucket",
			roles: []string{
				"arn:aws:iam::619888638459:role/s3-test-assume-role",
			},
			wantErrCount: 0,
		},
		{
			name: "roles without buckets, one error per role that cannot access any account buckets",
			roles: []string{
				"arn:aws:iam::619888638459:role/s3-test-assume-role",
				"arn:aws:iam::619888638459:role/test-no-access",
			},
			wantErrCount: 1,
		},
		{
			name: "role and buckets, can access at least one bucket",
			roles: []string{
				"arn:aws:iam::619888638459:role/s3-test-assume-role",
			},
			buckets: []string{
				"truffletestbucket-s3-role-assumption",
				"truffletestbucket-no-access",
			},
			wantErrCount: 0,
		},
		{
			name: "roles and buckets, one error per role that cannot access at least one bucket",
			roles: []string{
				"arn:aws:iam::619888638459:role/s3-test-assume-role",
				"arn:aws:iam::619888638459:role/test-no-access",
			},
			buckets: []string{
				"truffletestbucket-s3-role-assumption",
				"truffletestbucket-no-access",
			},
			wantErrCount: 1,
		},
		{
			name: "role and buckets, a bucket doesn't even exist",
			roles: []string{
				"arn:aws:iam::619888638459:role/s3-test-assume-role",
			},
			buckets: []string{
				"truffletestbucket-s3-role-assumption",
				"not-a-real-bucket-asljdhmglasjgvklhsdaljfh", // need a bucket name that nobody is likely to ever create
			},
			wantErrCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
			var cancelOnce sync.Once
			defer cancelOnce.Do(cancel)

			s := &Source{}

			// As of this writing, credentials set in the environment or the on-disk credentials file also work, but I
			// couldn't figure out how to write automated tests for those cases that weren't ugly as sin.
			conn, err := anypb.New(&sourcespb.S3{
				Credential: &sourcespb.S3_AccessKey{
					AccessKey: &credentialspb.KeySecret{
						Key:    s3key,
						Secret: s3secret,
					},
				},
				Buckets:       tt.buckets,
				IgnoreBuckets: tt.ignoreBuckets,
				Roles:         tt.roles,
			})
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.name, 0, 0, false, conn, 0)
			if err != nil {
				t.Fatal(err)
			}

			errs := s.Validate(ctx)

			assert.Equal(t, tt.wantErrCount, len(errs))
		})
	}
}

func TestSourceChunksNoResumption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bucket         string
		wantChunkCount int
	}{
		{
			bucket:         "trufflesec-ahrav-test-2",
			wantChunkCount: 19787,
		},
		{
			bucket:         "integration-resumption-tests",
			wantChunkCount: 19787,
		},
	}

	for _, tt := range tests {
		t.Run(tt.bucket, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()

			s := Source{}
			connection := &sourcespb.S3{
				Credential: &sourcespb.S3_Unauthenticated{},
				Buckets:    []string{tt.bucket},
			}
			conn, err := anypb.New(connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, "test name", 0, 0, false, conn, 1)
			chunksCh := make(chan *sources.Chunk)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				assert.Nil(t, err)
			}()

			got := 0
			for range chunksCh {
				got++
			}
			assert.Equal(t, tt.wantChunkCount, got)
		})
	}
}

func TestSourceChunksResumption(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := new(Source)
	src.Progress = sources.Progress{
		Message:           "Bucket: integration-resumption-tests",
		EncodedResumeInfo: "{\"current_bucket\":\"integration-resumption-tests\",\"start_after\":\"test-dir/\"}",
		SectionsCompleted: 0,
		SectionsRemaining: 1,
	}
	connection := &sourcespb.S3{
		Credential:       &sourcespb.S3_Unauthenticated{},
		Buckets:          []string{"integration-resumption-tests"},
		EnableResumption: true,
	}
	conn, err := anypb.New(connection)
	require.NoError(t, err)

	err = src.Init(ctx, "test name", 0, 0, false, conn, 2)
	require.NoError(t, err)

	chunksCh := make(chan *sources.Chunk)
	var count int

	cancelCtx, ctxCancel := context.WithCancel(ctx)
	defer ctxCancel()

	go func() {
		defer close(chunksCh)
		err = src.Chunks(cancelCtx, chunksCh)
		assert.NoError(t, err, "Should not error during scan")
	}()

	for range chunksCh {
		count++
	}

	// Verify that we processed all remaining data on resume.
	// Also verify that we processed less than the total number of chunks for the source.
	sourceTotalChunkCount := 19787
	assert.Equal(t, 9638, count, "Should have processed all remaining data on resume")
	assert.Less(t, count, sourceTotalChunkCount, "Should have processed less than total chunks on resume")
}

func TestSourceChunksNoResumptionMultipleBuckets(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	s := Source{}
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Buckets:    []string{"integration-resumption-tests", "truffletestbucket"},
	}
	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "test name", 0, 0, false, conn, 1)
	chunksCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunksCh)
		err = s.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	wantChunkCount := 19890
	got := 0

	for range chunksCh {
		got++
	}
	assert.Equal(t, wantChunkCount, got)
}

func TestSourceChunksResumptionMultipleBucketsIgnoredBucket(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := new(Source)

	// The bucket stored in EncodedResumeInfo is NOT in the list of buckets to scan.
	// Therefore, resume from the other provided bucket (truffletestbucket).
	src.Progress = sources.Progress{
		Message:           "Bucket: integration-resumption-tests",
		EncodedResumeInfo: "{\"current_bucket\":\"integration-resumption-tests\",\"start_after\":\"test-dir/\"}",
		SectionsCompleted: 0,
		SectionsRemaining: 1,
	}
	connection := &sourcespb.S3{
		Credential:       &sourcespb.S3_Unauthenticated{},
		Buckets:          []string{"truffletestbucket"},
		EnableResumption: true,
	}
	conn, err := anypb.New(connection)
	require.NoError(t, err)

	err = src.Init(ctx, "test name", 0, 0, false, conn, 2)
	require.NoError(t, err)

	chunksCh := make(chan *sources.Chunk)
	var count int

	cancelCtx, ctxCancel := context.WithCancel(ctx)
	defer ctxCancel()

	go func() {
		defer close(chunksCh)
		err = src.Chunks(cancelCtx, chunksCh)
		assert.NoError(t, err, "Should not error during scan")
	}()

	for range chunksCh {
		count++
	}

	assert.Equal(t, 103, count, "Should have processed all remaining data on resume")
}

func TestSource_Enumerate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    s3key,
				Secret: s3secret,
			},
		},
		Buckets: []string{"truffletestbucket"},
	}

	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	s := Source{}
	err = s.Init(ctx, "test enumerate", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.NoError(t, err)

	assert.Equal(t, len(reporter.Units), 1)
	assert.Equal(t, 0, len(reporter.UnitErrs), "Expected no errors during enumeration")

	for _, unit := range reporter.Units {
		id, _ := unit.SourceUnitID()
		assert.NotEmpty(t, id, "Unit ID should not be empty")
	}
}

func TestSource_ChunkUnit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    s3key,
				Secret: s3secret,
			},
		},
		Buckets: []string{"truffletestbucket"},
	}

	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	s := Source{}
	err = s.Init(ctx, "test enumerate", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.NoError(t, err)

	for _, unit := range reporter.Units {
		err = s.ChunkUnit(ctx, unit, &reporter)
		assert.NoError(t, err, "Expected no error during ChunkUnit")
	}

	assert.Equal(t, 103, len(reporter.Chunks))
	assert.Equal(t, 0, len(reporter.ChunkErrs))
}

func TestSource_ChunkUnit_Resumption(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Second)
	defer cancel()

	s := new(Source)
	s.Progress = sources.Progress{
		Message:           "Bucket: integration-resumption-tests",
		EncodedResumeInfo: "{\"integration-resumption-tests\":\"test-dir/\"}",
		SectionsCompleted: 0,
		SectionsRemaining: 1,
	}
	connection := &sourcespb.S3{
		Credential:       &sourcespb.S3_Unauthenticated{},
		Buckets:          []string{"integration-resumption-tests"},
		EnableResumption: true,
	}
	conn, err := anypb.New(connection)
	require.NoError(t, err)

	err = s.Init(ctx, "test name", 0, 0, false, conn, 2)
	require.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.NoError(t, err)

	for _, unit := range reporter.Units {
		err = s.ChunkUnit(ctx, unit, &reporter)
		assert.NoError(t, err, "Expected no error during ChunkUnit")
	}

	// Verify that we processed all remaining data on resume.
	assert.Equal(t, 9638, len(reporter.Chunks), "Should have processed all remaining data on resume")
}
