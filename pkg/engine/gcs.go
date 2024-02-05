package engine

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gcs"
)

// ScanGCS with the provided options.
func (e *Engine) ScanGCS(ctx context.Context, c sources.GCSConfig) error {
	// Project ID is required if using any authenticated access.
	if c.ProjectID == "" && !c.WithoutAuth {
		return fmt.Errorf("project ID is required")
	}

	// If using unauthenticated access, the project ID is not used.
	if c.ProjectID != "" && c.WithoutAuth {
		c.ProjectID = ""
		ctx.Logger().Info("project ID is not used when using unauthenticated access, ignoring provided project ID")
	}

	connection := &sourcespb.GCS{
		ProjectId:      c.ProjectID,
		IncludeBuckets: c.IncludeBuckets,
		ExcludeBuckets: c.ExcludeBuckets,
		IncludeObjects: c.IncludeObjects,
		ExcludeObjects: c.ExcludeObjects,
	}

	// Make sure only one auth method is selected.
	if !isAuthValid(ctx, c, connection) {
		return fmt.Errorf("multiple auth methods selected, please select only one")
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		return fmt.Errorf("failed to marshal GCS connection: %w", err)
	}

	sourceName := "trufflehog - gcs"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, gcs.SourceType)

	gcsSource := &gcs.Source{}
	if err := gcsSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, int(c.Concurrency)); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, gcsSource)
	return err
}

func isAuthValid(ctx context.Context, c sources.GCSConfig, connection *sourcespb.GCS) bool {
	var isAuthSelected bool

	if c.WithoutAuth {
		isAuthSelected = true
		connection.Credential = &sourcespb.GCS_Unauthenticated{}
	}
	if c.CloudCred {
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
		connection.Credential = &sourcespb.GCS_ServiceAccountFile{
			ServiceAccountFile: c.ServiceAccount,
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
