package npm

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Source struct {
	name     string
	sourceId int64
	jobId    int64
	verify   bool
	sources.Progress
	client *http.Client
}

// Ensure the Source satisfies the interface at compile time
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_NPM
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized Filesystem source.
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, _ int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.client = common.RetryableHttpClientTimeout(3)

	var conn sourcespb.NPM
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {

	return nil
}

func (s *Source) getPackage(ctx context.Context, packageName string) (*pkg, error) {
	reqURL := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode > 299 || res.StatusCode < 200 {
		return nil, fmt.Errorf("error getting package: %s", res.Status)
	}

	var packageRes *pkg
	if err := json.NewDecoder(res.Body).Decode(&packageRes); err != nil {
		return nil, err
	}

	return packageRes, nil
}

func (s *Source) getPackagesByMaintainer(ctx context.Context, maintainerName string) (*maintainerRes, error) {
	reqURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=maintainer:%s&from=0&size=1000", maintainerName)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode > 299 || res.StatusCode < 200 {
		return nil, fmt.Errorf("error getting package: %s", res.Status)
	}

	var maintRes *maintainerRes
	if err := json.NewDecoder(res.Body).Decode(&maintRes); err != nil {
		return nil, err
	}

	return maintRes, nil
}
