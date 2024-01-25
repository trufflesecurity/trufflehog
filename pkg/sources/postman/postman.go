package postman

import (
	"context"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_POSTMAN
)

type Source struct {
	name        string
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	concurrency int
	log         logr.Logger
	sources.Progress
	jobPool *errgroup.Group
	client  *Client
	sources.CommonSourceUnitUnmarshaller
}

// Init returns an initialized TravisCI source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.Postman
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	switch conn.Credential.(type) {
	case *sourcespb.Postman_Token:
		if conn.GetToken() == "" {
			return errors.New("Postman token is empty")
		}
		s.client = NewClient(conn.GetToken())
		s.client.HTTPClient = common.RetryableHttpClientTimeout(3)

		//Consider adding an auth check here. But even if token is valid, doesn't mean we have access to the target source. So unnecssary?
	case *sourcespb.Postman_Unauthenticated:
		s.client = nil
		// No client needed, since reading from local
	default:
		return errors.New("credential type not implemented for Travis CI")
	}

	return nil
}
