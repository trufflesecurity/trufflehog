package engine

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gitlab"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"runtime"
)

func (e *Engine) ScanGitLab(ctx context.Context, endpoint, token string, repositories []string) error {
	connection := &sourcespb.GitLab{}

	switch {
	case len(token) > 0:
		connection.Credential = &sourcespb.GitLab_Token{
			Token: token,
		}
	default:
		return fmt.Errorf("must provide token")
	}

	if len(endpoint) > 0 {
		connection.Endpoint = endpoint
	}

	if len(repositories) > 0 {
		connection.Repositories = repositories
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to marshal gitlab connection")
		return err
	}

	gitlabSource := gitlab.Source{}
	err = gitlabSource.Init(ctx, "trufflehog - gitlab", 0, int64(sourcespb.SourceType_SOURCE_TYPE_GITLAB), true, &conn, runtime.NumCPU(), nil)
	if err != nil {
		return errors.WrapPrefix(err, "could not init GitLab source", 0)
	}
	go func() {
		err := gitlabSource.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Error("error scanning GitLab")
		}
		close(e.ChunksChan())
	}()
	return nil
}
