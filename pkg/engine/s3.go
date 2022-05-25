package engine

import (
	"context"
	"fmt"
	"runtime"

	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/s3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func (e *Engine) ScanS3(ctx context.Context, key, secret string, cloudCred bool, buckets []string) error {
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
	}
	if cloudCred {
		if len(key) > 0 || len(secret) > 0 {
			return fmt.Errorf("cannot use cloud credentials and basic auth together")
		}
		connection.Credential = &sourcespb.S3_CloudEnvironment{}
	}
	if len(key) > 0 && len(secret) > 0 {
		connection.Credential = &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    key,
				Secret: secret,
			},
		}
	}
	if len(buckets) > 0 {
		connection.Buckets = buckets
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to marshal github connection")
		return err
	}

	s3Source := s3.Source{}
	err = s3Source.Init(ctx, "trufflehog - s3", 0, int64(sourcespb.SourceType_SOURCE_TYPE_S3), true, &conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "failed to init S3 source", 0)
	}

	e.sourcesWg.Add(1)
	go func() {
		defer e.sourcesWg.Done()
		err := s3Source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Error("error scanning s3")
		}
	}()
	return nil
}
