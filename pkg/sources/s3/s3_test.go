package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

func TestSource_Init_IncludeAndIgnoreBucketsError(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    "ignored for test",
				Secret: "ignore for test",
			},
		},
		Buckets:       []string{"a"},
		IgnoreBuckets: []string{"b"},
	})
	assert.NoError(t, err)

	s := Source{}
	err = s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1)

	assert.Error(t, err)
}
