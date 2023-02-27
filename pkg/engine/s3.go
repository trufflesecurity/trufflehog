package engine

import (
	"fmt"
	"runtime"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
		if len(c.Key) > 0 || len(c.Secret) > 0 {
			return fmt.Errorf("cannot use cloud credentials and basic auth together")
		}
		connection.Credential = &sourcespb.S3_CloudEnvironment{}
	}
	if len(c.Key) > 0 && len(c.Secret) > 0 {
		connection.Credential = &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    c.Key,
				Secret: c.Secret,
			},
		}
	}
	if len(c.Buckets) > 0 {
		connection.Buckets = c.Buckets
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal S3 connection")
		return err
	}

	s3Source := s3.Source{}
	ctx = context.WithValues(ctx,
		"source_type", s3Source.Type().String(),
		"source_name", "s3",
	)
	err = s3Source.Init(ctx, "trufflehog - s3", 0, int64(sourcespb.SourceType_SOURCE_TYPE_S3), true, &conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "failed to init S3 source", 0)
	}

	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := s3Source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			ctx.Logger().Error(err, "error scanning S3")
		}
	}()
	return nil
}
