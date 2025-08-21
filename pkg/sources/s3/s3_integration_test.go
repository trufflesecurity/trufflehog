//go:build integration
// +build integration

package s3

import (
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
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

func TestSource_Chunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.S3
		setEnv     map[string]string
	}
	tests := []struct {
		name          string
		init          init
		wantErr       bool
		wantChunkData string
	}{
		{
			name: "gets chunks",
			init: init{
				connection: &sourcespb.S3{
					Credential: &sourcespb.S3_AccessKey{
						AccessKey: &credentialspb.KeySecret{
							Key:    s3key,
							Secret: s3secret,
						},
					},
					Buckets: []string{"truffletestbucket-s3-tests"},
				},
			},
			wantErr:       false,
			wantChunkData: `W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lkID0gQUtJQTM1T0hYMkRTT1pHNjQ3TkgKYXdzX3NlY3JldF9hY2Nlc3Nfa2V5ID0gUXk5OVMrWkIvQ1dsRk50eFBBaWQ3Z0d6dnNyWGhCQjd1ckFDQUxwWgpvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`,
		},
		{
			name: "gets chunks after assuming role",
			// This test will attempt to scan every bucket in the account, but the role policy blocks access to every
			// bucket except the one we want. This (expected behavior) causes errors in the test log output, but these
			// errors shouldn't actually cause test failures.
			init: init{
				connection: &sourcespb.S3{
					Roles: []string{"arn:aws:iam::619888638459:role/s3-test-assume-role"},
				},
				setEnv: map[string]string{
					"AWS_ACCESS_KEY_ID":     s3key,
					"AWS_SECRET_ACCESS_KEY": s3secret,
				},
			},
			wantErr:       false,
			wantChunkData: `W2RlZmF1bHRdCmF3c19zZWNyZXRfYWNjZXNzX2tleSA9IFF5OTlTK1pCL0NXbEZOdHhQQWlkN2dHenZzclhoQkI3dXJBQ0FMcFoKYXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMzVPSFgyRFNPWkc2NDdOSApvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "gets chunks after assuming role" {
				t.Skip("skipping until our test environment stabilizes enough that we know how we're going to handle this")
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()

			for k, v := range tt.init.setEnv {
				t.Setenv(k, v)
			}

			s := Source{}
			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					os.Exit(1)
				}
			}()

			waitFn := func() {
				receivedFirstChunk := false
				for {
					select {
					case <-ctx.Done():
						t.Errorf("TestSource_Chunks timed out: %v", ctx.Err())
						return
					case gotChunk, ok := <-chunksCh:
						if !ok {
							t.Logf("Source.Chunks() finished, channel closed")
							assert.Equal(t, "", s.GetProgress().EncodedResumeInfo)
							assert.Equal(t, int64(100), s.GetProgress().PercentComplete)
							return
						}
						if receivedFirstChunk {
							// wantChunkData is the first chunk data. After the first chunk has
							// been received and matched below, we want to drain chunksCh
							// so Source.Chunks() can finish completely.
							continue
						}

						receivedFirstChunk = true
						wantData, _ := base64.StdEncoding.DecodeString(tt.wantChunkData)

						if diff := pretty.Compare(gotChunk.Data, wantData); diff != "" {
							t.Logf("%s: Source.Chunks() diff: (-got +want)\n%s", tt.name, diff)
						}
					}
				}
			}
			waitFn()
		})
	}
}

func TestSource_Chunks_TargetedScanning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Skipf("Failed to access secret: %v", err)
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	// Create S3 source
	s := Source{}
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    s3key,
				Secret: s3secret,
			},
		},
		Buckets: []string{"truffletestbucket-s3-tests"},
	})
	require.NoError(t, err)

	err = s.Init(ctx, "s3 test source for targeted scanning", 0, 0, false, conn, 8)
	require.NoError(t, err)

	// First, let's find what objects are actually in the bucket by running a regular scan
	// and capturing the first chunk to get its metadata
	var actualBucket string
	var actualKey string
	var actualData []byte

	// Run a quick scan to discover available objects
	tempChunksCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(tempChunksCh)
		_ = s.Chunks(ctx, tempChunksCh)
	}()

	// Get the first chunk to extract actual S3 metadata
	select {
	case <-ctx.Done():
		t.Fatal("Failed to get sample chunk for S3 metadata")
	case chunk, ok := <-tempChunksCh:
		require.True(t, ok, "Should receive at least one chunk from regular scan")

		// Extract the S3 metadata from the chunk
		s3Meta, ok := chunk.SourceMetadata.GetData().(*source_metadatapb.MetaData_S3)
		require.True(t, ok, "First chunk should have S3 metadata")

		actualBucket = s3Meta.S3.GetBucket()
		actualKey = s3Meta.S3.GetFile()
		actualData = chunk.Data

		t.Logf("Found S3 object: bucket=%s, key=%s, size=%d bytes", actualBucket, actualKey, len(actualData))

		// Drain remaining chunks
		for range tempChunksCh {
		}
	}

	require.NotEmpty(t, actualBucket, "Should have found a bucket")
	require.NotEmpty(t, actualKey, "Should have found a key")
	require.NotEmpty(t, actualData, "Should have found data")

	// Create a ChunkingTarget with the actual S3 metadata we discovered
	target := sources.ChunkingTarget{
		SecretID: 12345,
		QueryCriteria: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_S3{
				S3: &source_metadatapb.S3{
					Bucket: actualBucket,
					File:   actualKey,
					Link:   fmt.Sprintf("s3://%s/%s", actualBucket, actualKey),
					Email:  "test@trufflesecurity.com",
				},
			},
		},
	}

	// Test targeted scanning
	chunksCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunksCh)
		err = s.Chunks(ctx, chunksCh, target)
		assert.NoError(t, err)
	}()

	// Wait for and verify the chunk
	select {
	case <-ctx.Done():
		t.Fatal("TestSource_Chunks_TargetedScanning timed out")
	case chunk, ok := <-chunksCh:
		require.True(t, ok, "Should receive at least one chunk")

		// Verify the chunk has the right properties
		assert.Equal(t, SourceType, chunk.SourceType)
		assert.Equal(t, sources.SourceID(0), chunk.SourceID)
		assert.Equal(t, sources.JobID(0), chunk.JobID)
		assert.Equal(t, int64(12345), chunk.SecretID)
		assert.False(t, chunk.Verify)

		// Verify the metadata
		require.NotNil(t, chunk.SourceMetadata)
		s3Meta, ok := chunk.SourceMetadata.GetData().(*source_metadatapb.MetaData_S3)
		require.True(t, ok, "Metadata should be S3 type")
		assert.Equal(t, actualBucket, s3Meta.S3.GetBucket())
		assert.Equal(t, actualKey, s3Meta.S3.GetFile())
		assert.Equal(t, fmt.Sprintf("s3://%s/%s", actualBucket, actualKey), s3Meta.S3.GetLink())
		assert.Equal(t, "test@trufflesecurity.com", s3Meta.S3.GetEmail())

		// Verify the chunk has data (should match the content we discovered from regular scan)
		assert.Equal(t, actualData, chunk.Data, "Chunk data should match the S3 object content from targeted scan")

		t.Logf("Successfully received targeted chunk: bucket=%s, key=%s, size=%d bytes",
			s3Meta.S3.GetBucket(), s3Meta.S3.GetFile(), len(chunk.Data))
	}
}
