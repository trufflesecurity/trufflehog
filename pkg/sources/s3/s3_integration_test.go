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

	wantChunkCount := 120
	got := 0

	for range chunksCh {
		got++
	}
	assert.Greater(t, got, wantChunkCount)
}

type validationTestCase struct {
	name         string
	roles        []string
	buckets      []string
	wantErrCount int
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

	tests := []validationTestCase{
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
		//setupCreds := func(t *testing.T) {
		//	t.Setenv("AWS_ACCESS_KEY_ID", s3key)
		//	t.Setenv("AWS_SECRET_ACCESS_KEY", s3secret)
		//}
		//cfg := &sourcespb.S3{
		//	Credential: &sourcespb.S3_AccessKey{
		//		AccessKey: &credentialspb.KeySecret{
		//			Key:    s3key,
		//			Secret: s3secret,
		//		},
		//	},
		//}
		//name, f := buildValidateTestFunc(s3key, s3secret, tt)
		//t.Run(name, f)
		runTestCase(t, tt, s3key, s3secret, credentialLocation_CONFIG)
		runTestCase(t, tt, s3key, s3secret, credentialLocation_ENV)
	}
}

type credentialLocation int

const (
	credentialLocation_CONFIG = iota
	credentialLocation_ENV
)

func runTestCase(t *testing.T, tt validationTestCase, s3key, s3secret string, credLoc credentialLocation) {
	//cfg := &sourcespb.S3{}
	name := tt.name
	var setupCreds func(t *testing.T, cfg *sourcespb.S3)

	if credLoc == credentialLocation_CONFIG {
		setupCreds = func(_ *testing.T, cfg *sourcespb.S3) {
			cfg.Credential = &sourcespb.S3_AccessKey{
				AccessKey: &credentialspb.KeySecret{
					Key:    s3key,
					Secret: s3secret,
				},
			}
		}
		name += " [creds in config]"
	} else {
		setupCreds = func(t *testing.T, _ *sourcespb.S3) {
			//t.Setenv("AWS_ACCESS_KEY_ID", s3key)
			//t.Setenv("AWS_SECRET_ACCESS_KEY", s3secret)
		}
		name += " [creds in env]"
	}

	t.Run(name, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		var cancelOnce sync.Once
		defer cancelOnce.Do(cancel)

		// These are used by the tests that assume roles
		//t.Setenv("AWS_ACCESS_KEY_ID", s3key)
		//t.Setenv("AWS_SECRET_ACCESS_KEY", s3secret)

		s := &Source{}

		//cfg.Buckets = tt.buckets
		//cfg.Roles = tt.roles

		cfg := &sourcespb.S3{
			Buckets: tt.buckets,
			Roles:   tt.roles,
		}
		setupCreds(t, cfg)

		//conn, err := anypb.New(&sourcespb.S3{
		//	// These are used by the tests that don't assume roles
		//	Credential: &sourcespb.S3_AccessKey{
		//		AccessKey: &credentialspb.KeySecret{
		//			Key:    s3key,
		//			Secret: s3secret,
		//		},
		//	},
		//	Buckets: tt.buckets,
		//	Roles:   tt.roles,
		//})
		conn, err := anypb.New(cfg)
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

func buildValidateTestFunc(s3key, s3secret string, tt validationTestCase) (string, func(t *testing.T)) {
	setupCreds := func(t *testing.T, cfg *sourcespb.S3) {
		t.Setenv("AWS_ACCESS_KEY_ID", s3key)
		t.Setenv("AWS_SECRET_ACCESS_KEY", s3secret)

		cfg.Credential = &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    s3key,
				Secret: s3secret,
			},
		}
	}

	return tt.name, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		var cancelOnce sync.Once
		defer cancelOnce.Do(cancel)

		// These are used by the tests that assume roles
		//t.Setenv("AWS_ACCESS_KEY_ID", s3key)
		//t.Setenv("AWS_SECRET_ACCESS_KEY", s3secret)

		s := &Source{}

		cfg := &sourcespb.S3{
			Buckets: tt.buckets,
			Roles:   tt.roles,
		}
		setupCreds(t, cfg)

		//conn, err := anypb.New(&sourcespb.S3{
		//	// These are used by the tests that don't assume roles
		//	Credential: &sourcespb.S3_AccessKey{
		//		AccessKey: &credentialspb.KeySecret{
		//			Key:    s3key,
		//			Secret: s3secret,
		//		},
		//	},
		//	Buckets: tt.buckets,
		//	Roles:   tt.roles,
		//})
		conn, err := anypb.New(cfg)
		if err != nil {
			t.Fatal(err)
		}

		err = s.Init(ctx, tt.name, 0, 0, false, conn, 0)
		if err != nil {
			t.Fatal(err)
		}

		errs := s.Validate(ctx)

		assert.Equal(t, tt.wantErrCount, len(errs))
	}
}
