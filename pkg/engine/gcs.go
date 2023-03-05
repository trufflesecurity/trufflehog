package engine

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gcs"
)

// ScanGCS scans GCS with the provided options.
func (e *Engine) ScanGCS(ctx context.Context, c sources.GCSConfig) error {
	if c.ProjectID == "" {
		return fmt.Errorf("project ID is required")
	}

	connection := &sourcespb.GCS{
		ProjectId:      c.ProjectID,
		IncludeBuckets: c.IncludeBuckets,
		ExcludeBuckets: c.ExcludeBuckets,
		IncludeObjects: c.IncludeObjects,
		ExcludeObjects: c.ExcludeObjects,
	}

	// Make sure only one auth method is selected.
	if ok := isAuthValid(ctx, c, connection); !ok {
		return fmt.Errorf("multiple auth methods selected, please select only one")
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		return fmt.Errorf("failed to marshal GCS connection: %w", err)
	}

	source := gcs.Source{}
	ctx = context.WithValues(ctx,
		"source_type", source.Type().String(),
		"source_name", "gcs",
	)
	if err = source.Init(ctx, "trufflehog - GCS", 0, 0, true, &conn, c.Concurrency); err != nil {
		return fmt.Errorf("failed to initialize GCS source: %w", err)
	}

	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		if err := source.Chunks(ctx, e.ChunksChan()); err != nil {
			ctx.Logger().Error(err, "could not scan GCS")
		}
	}()
	return nil
}

func isAuthValid(ctx context.Context, c sources.GCSConfig, connection *sourcespb.GCS) bool {
	var isAuthSelected bool

	if c.WithoutAuth {
		isAuthSelected = true
		connection.Credential = &sourcespb.GCS_Unauthenticated{}
	}
	if c.WithADC {
		if isAuthSelected {
			return false
		}
		isAuthSelected = true
		connection.Credential = &sourcespb.GCS_Adc{}
	}
	if c.ServiceAccount != "" {
		if isAuthSelected {
			return false
		}
		isAuthSelected = true
		connection.Credential = &sourcespb.GCS_JsonSa{
			JsonSa: c.ServiceAccount,
		}
	}
	if c.ApiKey != "" {
		if isAuthSelected {
			return false
		}
		isAuthSelected = true
		connection.Credential = &sourcespb.GCS_ApiKey{
			ApiKey: c.ApiKey,
		}
	}
	if !isAuthSelected {
		ctx.Logger().Info("no auth method selected, using unauthenticated")
		connection.Credential = &sourcespb.GCS_Unauthenticated{}
	}

	return true
}
