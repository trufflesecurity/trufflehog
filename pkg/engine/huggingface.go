package engine

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/huggingface"
)

// HuggingFaceConfig represents the configuration for HuggingFace.
type HuggingfaceConfig struct {
	Endpoint           string
	Models             []string
	Spaces             []string
	Datasets           []string
	Organizations      []string
	Users              []string
	IncludeModels      []string
	IgnoreModels       []string
	IncludeSpaces      []string
	IgnoreSpaces       []string
	IncludeDatasets    []string
	IgnoreDatasets     []string
	SkipAllModels      bool
	SkipAllSpaces      bool
	SkipAllDatasets    bool
	IncludeDiscussions bool
	IncludePrs         bool
	Token              string
	Concurrency        int
}

// ScanGitHub scans HuggingFace with the provided options.
func (e *Engine) ScanHuggingface(ctx context.Context, c HuggingfaceConfig) error {
	connection := sourcespb.Huggingface{
		Endpoint:           c.Endpoint,
		Models:             c.Models,
		Spaces:             c.Spaces,
		Datasets:           c.Datasets,
		Organizations:      c.Organizations,
		Users:              c.Users,
		IncludeModels:      c.IncludeModels,
		IgnoreModels:       c.IgnoreModels,
		IncludeSpaces:      c.IncludeSpaces,
		IgnoreSpaces:       c.IgnoreSpaces,
		IncludeDatasets:    c.IncludeDatasets,
		IgnoreDatasets:     c.IgnoreDatasets,
		SkipAllModels:      c.SkipAllModels,
		SkipAllSpaces:      c.SkipAllSpaces,
		SkipAllDatasets:    c.SkipAllDatasets,
		IncludeDiscussions: c.IncludeDiscussions,
		IncludePrs:         c.IncludePrs,
	}
	if len(c.Token) > 0 {
		connection.Credential = &sourcespb.Huggingface_Token{
			Token: c.Token,
		}
	} else {
		connection.Credential = &sourcespb.Huggingface_Unauthenticated{}
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal huggingface connection")
		return err
	}

	sourceName := "trufflehog - huggingface"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, sourcespb.SourceType_SOURCE_TYPE_HUGGINGFACE)

	huggingfaceSource := &huggingface.Source{}
	if err := huggingfaceSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, c.Concurrency); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, huggingfaceSource)
	return err
}
