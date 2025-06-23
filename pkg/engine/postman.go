package engine

import (
	"errors"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/postman"
)

// ScanPostman scans Postman with the provided options.
func (e *Engine) ScanPostman(ctx context.Context, c sources.PostmanConfig) (sources.JobProgressRef, error) {
	connection := sourcespb.Postman{
		Workspaces:          c.Workspaces,
		Collections:         c.Collections,
		Environments:        c.Environments,
		IncludeCollections:  c.IncludeCollections,
		IncludeEnvironments: c.IncludeEnvironments,
		ExcludeCollections:  c.ExcludeCollections,
		ExcludeEnvironments: c.ExcludeEnvironments,
		WorkspacePaths:      c.WorkspacePaths,
		CollectionPaths:     c.CollectionPaths,
		EnvironmentPaths:    c.EnvironmentPaths,
	}

	// Check if postman data is going to be accessed via an api call using a token, or
	// if it has been already exported and exists locally
	if len(c.Token) > 0 {
		connection.Credential = &sourcespb.Postman_Token{
			Token: c.Token,
		}
	} else if len(c.WorkspacePaths) > 0 || len(c.CollectionPaths) > 0 || len(c.EnvironmentPaths) > 0 {
		connection.Credential = &sourcespb.Postman_Unauthenticated{}
	} else {
		return sources.JobProgressRef{}, errors.New("no path to locally exported data or API token provided")
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Postman connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - postman"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, postman.SourceType)

	postmanSource := &postman.Source{
		DetectorKeywords: e.AhoCorasickCoreKeywords(),
	}

	if err := postmanSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, c.Concurrency); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, postmanSource)
}
