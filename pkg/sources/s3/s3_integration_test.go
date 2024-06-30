//go:build integration
// +build integration

package s3

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
