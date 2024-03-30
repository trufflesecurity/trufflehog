package engine

import (
	"fmt"
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/s3"
)

// ScanS3 scans S3 buckets.
func (e *Engine) ScanS3(ctx context.Context, c sources.S3Config) error {
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
	}
	if c.CloudCred {
		if len(c.Key) > 0 || len(c.Secret) > 0 || len(c.SessionToken) > 0 {
			return fmt.Errorf("cannot use cloud environment and static credentials together")
		}
		connection.Credential = &sourcespb.S3_CloudEnvironment{}
	}
	if len(c.Key) > 0 && len(c.Secret) > 0 {
		if len(c.SessionToken) > 0 {
			connection.Credential = &sourcespb.S3_SessionToken{
				SessionToken: &credentialspb.AWSSessionTokenSecret{
					Key:          c.Key,
					Secret:       c.Secret,
					SessionToken: c.SessionToken,
				},
			}
		} else {
			connection.Credential = &sourcespb.S3_AccessKey{
				AccessKey: &credentialspb.KeySecret{
					Key:    c.Key,
					Secret: c.Secret,
				},
			}
		}
	}
	if len(c.Buckets) > 0 {
		connection.Buckets = c.Buckets
	}
	if len(c.IgnoreBuckets) > 0 {
		connection.IgnoreBuckets = c.IgnoreBuckets
	}

	if len(c.Roles) > 0 {
		connection.Roles = c.Roles
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal S3 connection")
		return err
	}

	sourceName := "trufflehog - s3"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, s3.SourceType)

	s3Source := &s3.Source{}
	if err := s3Source.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, s3Source)
	return err
}
