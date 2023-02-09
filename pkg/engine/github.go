package engine

import (
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	gogit "github.com/go-git/go-git/v5"
	
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github"
)

// ScanGitHub scans Github with the provided options.
func (e *Engine) ScanGitHub(ctx context.Context, c sources.Config) error {
	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}
	scanOptions := git.NewScanOptions(opts...)
	
	source := github.Source{}

	connection := sourcespb.GitHub{
		Endpoint:      c.Endpoint,
		Organizations: c.Orgs,
		Repositories:  c.Repos,
		ScanUsers:     c.IncludeMembers,
		IgnoreRepos:   c.ExcludeRepos,
		IncludeRepos:  c.IncludeRepos,
	}
	if len(c.Token) > 0 {
		connection.Credential = &sourcespb.GitHub_Token{
			Token: c.Token,
		}
	} else {
		connection.Credential = &sourcespb.GitHub_Unauthenticated{}
	}
	connection.IncludeForks = c.IncludeForks
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to marshal github connection")
		return err
	}
	err = source.Init(ctx, "trufflehog - github", 0, 0, false, &conn, c.Concurrency)
	if err != nil {
		logrus.WithError(err).Error("failed to initialize github source")
		return err
	}
	source.WithScanOptions(scanOptions)
	
	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan github")
		}
	}()
	return nil
}
