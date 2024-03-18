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

// ScanGitHub scans Postman with the provided options.
func (e *Engine) ScanPostman(ctx context.Context, c sources.PostmanConfig) error {
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
	if len(c.Token) > 0 {
		connection.Credential = &sourcespb.Postman_Token{
			Token: c.Token,
		}
	} else {
		connection.Credential = &sourcespb.Postman_Unauthenticated{}
	}

	if len(c.Workspaces) == 0 && len(c.Collections) == 0 && len(c.Environments) == 0 && len(c.Token) == 0 && len(c.WorkspacePaths) == 0 && len(c.CollectionPaths) == 0 && len(c.EnvironmentPaths) == 0 {
		ctx.Logger().Error(errors.New("no postman workspaces, collections, environments or API token provided"), "failed to scan postman")
		return nil
	}

	// Turn AhoCorasick keywordsToDetectors into a map of keywords
	keywords := make(map[string]struct{})
	for key := range e.ahoCorasickCore.KeywordsToDetectors() {
		keywords[key] = struct{}{}
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Postman connection")
		return err
	}

	sourceName := "trufflehog - postman"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, postman.SourceType)

	postmanSource := &postman.Source{
		DetectorKeywords: keywords,
	}
	if err := postmanSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, c.Concurrency); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, postmanSource)
	return err
}
