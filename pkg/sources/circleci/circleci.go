package circleci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/go-errors/errors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_CIRCLECI

	// CircleCI has released API v2, but we're continuing to use v1.1 for now because it still supports listing endpoints and remains officially supported.
	baseURL = "https://circleci.com/api/v1.1"
)

type Source struct {
	name     string
	token    string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	jobPool  *errgroup.Group
	sources.Progress
	client *http.Client
	sources.CommonSourceUnitUnmarshaller
}

// CircleCI API Response types
type project struct {
	VCS      string `json:"vcs_type"`
	Username string `json:"username"`
	RepoName string `json:"reponame"`
	VCSUrl   string `json:"vcs_url"`
}

type build struct {
	BuildNum int `json:"build_num"`
}

type buildJobs struct {
	CircleYAML struct {
		YamlString string `json:"string"`
	} `json:"circle_yml"`
	Steps []buildStep `json:"steps"`
}

type buildStep struct {
	Name    string   `json:"name"`
	Actions []action `json:"actions"`
}

type action struct {
	Index     int    `json:"index"`
	OutputURL string `json:"output_url"`
}

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init returns an initialized CircleCI source.
func (s *Source) Init(_ context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)
	s.client = common.RetryableHTTPClientTimeout(3)

	var conn sourcespb.CircleCI
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	switch conn.Credential.(type) {
	case *sourcespb.CircleCI_Token:
		s.token = conn.GetToken()
		log.RedactGlobally(s.token)
	}

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	// TODO: list Artifacts, list checkout-keys, list env-variables

	// list all projects
	projects, err := s.listAllProjects(ctx)
	if err != nil {
		return fmt.Errorf("error getting projects: %w", err)
	}

	var countOfProjectsScanned uint64
	scanErrs := sources.NewScanErrors()

	for _, project := range projects {
		s.jobPool.Go(func() error {
			projectBuilds, err := s.listProjectBuilds(ctx, &project)
			if err != nil {
				scanErrs.Add(fmt.Errorf("error getting builds for project %s: %w", project.RepoName, err))
				return nil
			}

			for _, build := range projectBuilds {
				projBuildJobs, err := s.listProjBuildJobs(ctx, &project, &build)
				if err != nil {
					scanErrs.Add(fmt.Errorf("error getting steps for build %d: %w", build.BuildNum, err))
					return nil
				}

				for _, step := range projBuildJobs.Steps {
					for _, action := range step.Actions {
						if err = s.chunkAction(ctx, project, build, action, step.Name, chunksChan); err != nil {
							scanErrs.Add(fmt.Errorf("error chunking action %v: %w", action, err))
							return nil
						}
					}
				}

				if err = s.chunkCircleCIYamlString(ctx, project, build, projBuildJobs.CircleYAML.YamlString, chunksChan); err != nil {
					scanErrs.Add(fmt.Errorf("error chunking build yaml: %w", err))
					return nil
				}
			}

			atomic.AddUint64(&countOfProjectsScanned, 1)
			ctx.Logger().V(2).Info(fmt.Sprintf("scanned %d/%d projects", countOfProjectsScanned, len(projects)))
			return nil
		})
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().V(2).Info("encountered errors while scanning", "count", scanErrs.Count(), "errors", scanErrs)
	}

	return nil
}

// listAllProjects lists all the projects the token can access
func (s *Source) listAllProjects(ctx context.Context) ([]project, error) {
	ctx.Logger().V(5).Info("listing projects")
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/projects", baseURL), http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Circle-Token", s.token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var projects []project
		if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
			return nil, fmt.Errorf("cannot decode CircleCI projects JSON: %w", err)
		}

		ctx.Logger().V(2).Info(fmt.Sprintf("successfully listed %d projects", len(projects)))

		return projects, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("invalid credentials, status %d", resp.StatusCode)
	default:
		return nil, fmt.Errorf("unexpected status code: %d while listing projects", resp.StatusCode)
	}
}

func (s *Source) listProjectBuilds(ctx context.Context, proj *project) ([]build, error) {
	// the vcs url is in format //circleci.com/org-id/proj-id, so we need to remove the // and .com to use it in the API
	parsedURL, err := url.Parse(proj.VCSUrl)
	if err != nil {
		return nil, err
	}

	vcsURL := strings.ReplaceAll(parsedURL.Host, ".com", "") + parsedURL.Path // circleci/org-id/proj-id

	// update clean vcs url in the project for later use
	proj.VCSUrl = vcsURL

	ctx.Logger().V(5).Info(fmt.Sprintf("listing project: %s builds with URL: %s", proj.RepoName, proj.VCSUrl))

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/project/%s", baseURL, vcsURL), http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Circle-Token", s.token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var builds []build
		if err := json.NewDecoder(resp.Body).Decode(&builds); err != nil {
			return nil, fmt.Errorf("cannot decode CircleCI project builds JSON: %w", err)
		}

		ctx.Logger().V(2).Info(fmt.Sprintf("successfully listed %d builds for project: %s", len(builds), proj.RepoName))

		return builds, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("no builds found for project: %s", proj.RepoName)
	default:
		return nil, fmt.Errorf("unexpected status code while fetching builds for project: %s", proj.RepoName)
	}

}

func (s *Source) listProjBuildJobs(ctx context.Context, proj *project, projectBuild *build) (*buildJobs, error) {
	ctx.Logger().V(5).Info(fmt.Sprintf("listing project: %s build: %d jobs", proj.RepoName, projectBuild.BuildNum))
	// /project/circleci/org-id/proj-id/1
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/project/%s/%d", baseURL, proj.VCSUrl, projectBuild.BuildNum), http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Circle-Token", s.token)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var buildResp buildJobs
		if err := json.NewDecoder(resp.Body).Decode(&buildResp); err != nil {
			return nil, fmt.Errorf("cannot decode CircleCI project build jobs JSON: %w", err)
		}

		ctx.Logger().V(2).Info(fmt.Sprintf("successfully listed project: %s build: %d jobs", proj.RepoName, projectBuild.BuildNum))

		return &buildResp, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d while fetching project: %s build: %d jobs", resp.StatusCode, proj.RepoName, projectBuild.BuildNum)
	}
}

func (s *Source) chunkAction(ctx context.Context, proj project, projectBuild build, action action, stepName string, chunksChan chan *sources.Chunk) error {
	req, err := http.NewRequest(http.MethodGet, action.OutputURL, nil)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	linkURL := fmt.Sprintf("https://app.circleci.com/pipelines/%s/%s/%s/%d", proj.VCS, proj.Username, proj.RepoName, projectBuild.BuildNum)

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, resp.Body)
	for data := range chunkResChan {
		chunk := &sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			Data:       removeCircleSha1Line(data.Bytes()),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Circleci{
					Circleci: &source_metadatapb.CircleCI{
						VcsType:     proj.VCS,
						Username:    proj.Username,
						Repository:  proj.RepoName,
						BuildNumber: int64(projectBuild.BuildNum),
						BuildStep:   stepName,
						Link:        linkURL,
					},
				},
			},
			Verify: s.verify,
		}
		if err := data.Error(); err != nil {
			return err
		}

		if err := common.CancellableWrite(ctx, chunksChan, chunk); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) chunkCircleCIYamlString(ctx context.Context, proj project, projectBuild build, yamlString string, chunksChan chan *sources.Chunk) error {
	linkURL := fmt.Sprintf("https://app.circleci.com/pipelines/%s/%s/%s/%d", proj.VCS, proj.Username, proj.RepoName, projectBuild.BuildNum)

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, strings.NewReader(yamlString))
	for data := range chunkResChan {
		chunk := &sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			Data:       removeCircleSha1Line(data.Bytes()),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Circleci{
					Circleci: &source_metadatapb.CircleCI{
						VcsType:     proj.VCS,
						Username:    proj.Username,
						Repository:  proj.RepoName,
						BuildNumber: int64(projectBuild.BuildNum),
						BuildStep:   "",
						Link:        linkURL,
					},
				},
			},
			Verify: s.verify,
		}
		if err := data.Error(); err != nil {
			return err
		}

		if err := common.CancellableWrite(ctx, chunksChan, chunk); err != nil {
			return err
		}
	}

	return nil
}

func removeCircleSha1Line(input []byte) []byte {
	// Split the input slice into a slice of lines.
	lines := bytes.Split(input, []byte("\n"))

	// Iterate over the lines and add the ones that don't contain "CIRCLE_SHA1=" to the result slice.
	result := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if !bytes.Contains(line, []byte("CIRCLE_SHA1=")) {
			result = append(result, line)
		}
	}

	// Join the lines in the result slice and return the resulting slice.
	return bytes.Join(result, []byte("\n"))
}
