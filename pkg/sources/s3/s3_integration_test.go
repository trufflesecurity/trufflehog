//go:build integration
// +build integration

package s3

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
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

func TestSourceChunksNoResumption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	s := Source{}
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Buckets:    []string{"trufflesec-ahrav-test-2"},
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

	wantChunkCount := 19787
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

func TestSourceChunksResumption(t *testing.T) {
	// First scan - simulate interruption.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := new(Source)
	connection := &sourcespb.S3{
		Credential:       &sourcespb.S3_Unauthenticated{},
		Buckets:          []string{"trufflesec-ahrav-test-2"},
		EnableResumption: true,
	}
	conn, err := anypb.New(connection)
	require.NoError(t, err)

	err = src.Init(ctx, "test name", 0, 0, false, conn, 2)
	require.NoError(t, err)

	chunksCh := make(chan *sources.Chunk)
	var firstScanCount int64
	const cancelAfterChunks = 15_000

	cancelCtx, ctxCancel := context.WithCancel(ctx)
	defer ctxCancel()

	// Start first scan and collect chunks until chunk limit.
	go func() {
		defer close(chunksCh)
		err = src.Chunks(cancelCtx, chunksCh)
		assert.Error(t, err, "Expected context cancellation error")
	}()

	// Process chunks until we hit our limit
	for range chunksCh {
		firstScanCount++
		if firstScanCount >= cancelAfterChunks {
			ctxCancel() // Cancel context after processing desired number of chunks
			break
		}
	}

	// Verify we processed exactly the number of chunks we wanted.
	assert.Equal(t, int64(cancelAfterChunks), firstScanCount,
		"Should have processed exactly %d chunks in first scan", cancelAfterChunks)

	// Verify we have processed some chunks and have resumption info.
	assert.Greater(t, firstScanCount, int64(0), "Should have processed some chunks in first scan")

	progress := src.GetProgress()
	assert.NotEmpty(t, progress.EncodedResumeInfo, "Progress.EncodedResumeInfo should not be empty")

	firstScanCompletedIndex := progress.SectionsCompleted

	var resumeInfo ResumeInfo
	err = json.Unmarshal([]byte(progress.EncodedResumeInfo), &resumeInfo)
	require.NoError(t, err, "Should be able to decode resume info")

	// Verify resume info contains expected fields.
	assert.Equal(t, "trufflesec-ahrav-test-2", resumeInfo.CurrentBucket, "Resume info should contain correct bucket")
	assert.NotEmpty(t, resumeInfo.StartAfter, "Resume info should contain a StartAfter key")

	// Store the key where first scan stopped.
	firstScanLastKey := resumeInfo.StartAfter

	// Second scan - should resume from where first scan left off.
	ctx2 := context.Background()
	src2 := &Source{Progress: *src.GetProgress()}
	err = src2.Init(ctx2, "test name", 0, 0, false, conn, 4)
	require.NoError(t, err)

	chunksCh2 := make(chan *sources.Chunk)
	var secondScanCount int64

	go func() {
		defer close(chunksCh2)
		err = src2.Chunks(ctx2, chunksCh2)
		assert.NoError(t, err)
	}()

	// Process second scan chunks and verify progress.
	for range chunksCh2 {
		secondScanCount++

		// Get current progress during scan.
		currentProgress := src2.GetProgress()
		assert.GreaterOrEqual(t, currentProgress.SectionsCompleted, firstScanCompletedIndex,
			"Progress should be greater or equal to first scan")
		if currentProgress.EncodedResumeInfo != "" {
			var currentResumeInfo ResumeInfo
			err := json.Unmarshal([]byte(currentProgress.EncodedResumeInfo), &currentResumeInfo)
			require.NoError(t, err)

			// Verify that we're always scanning forward from where we left off.
			assert.GreaterOrEqual(t, currentResumeInfo.StartAfter, firstScanLastKey,
				"Second scan should never process keys before where first scan ended")
		}
	}

	// Verify total coverage.
	expectedTotal := int64(19787)
	actualTotal := firstScanCount + secondScanCount

	// Because of our resumption logic favoring completeness over speed, we can
	// re-scan some objects.
	assert.GreaterOrEqual(t, actualTotal, expectedTotal,
		"Total processed chunks should meet or exceed expected count")
	assert.Less(t, actualTotal, 2*expectedTotal,
		"Total processed chunks should not be more than double expected count")

	finalProgress := src2.GetProgress()
	assert.Equal(t, 1, int(finalProgress.SectionsCompleted), "Should have completed sections")
	assert.Equal(t, 1, int(finalProgress.SectionsRemaining), "Should have remaining sections")
}
