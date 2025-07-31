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

	// CircleCI has released API v2, but we're continuing to use v1.1
	// Because v1.1 still supports listing endpoints and remains officially supported.
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
	Reponame string `json:"reponame"`
	VcsUrl   string `json:"vcs_url"`
}

type BuildNum int

type buildJobs struct {
	CircleYaml struct {
		YamlString string `json:"string"`
	} `json:"circle_yml"`
	Steps []buildStep `json:"steps"`
}

type buildStep struct {
	Name    string   `json:"name"`
	Actions []action `json:"actions"`
}

type action struct {
	OutputUrl string `json:"output_url"`
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

	projects, err := s.listAllProjects(ctx)
	if err != nil {
		return fmt.Errorf("error getting projects: %w", err)
	}

	var countOfProjectsScanned atomic.Uint64
	var errors []error

	for _, project := range projects {
		ctx = context.WithValues(ctx,
			"repository_name", project.Reponame,
		)

		s.jobPool.Go(func() error {
			projectBuilds, err := s.listProjectBuilds(ctx, &project)
			if err != nil {
				ctx.Logger().Error(err, "error getting builds for project")
				errors = append(errors, err)

				return nil
			}

			for _, buildNum := range projectBuilds {
				ctx = context.WithValues(ctx,
					"build_number", buildNum,
				)

				projBuildJobs, err := s.listProjBuildJobs(ctx, &project, buildNum)
				if err != nil {
					ctx.Logger().Error(err, "error getting steps for build")
					errors = append(errors, err)

					continue
				}

				for _, step := range projBuildJobs.Steps {
					for _, action := range step.Actions {
						data, err := s.getOutputUrlResponse(action.OutputUrl)
						if err != nil {
							ctx.Logger().Error(err, "error getting action output url response")
							errors = append(errors, err)

							continue
						}

						if err = s.chunk(ctx, project, buildNum, step.Name, data, chunksChan); err != nil {
							ctx.Logger().Error(err, "error chunking action")
							errors = append(errors, err)

							continue
						}
					}
				}

				if err = s.chunk(ctx, project, buildNum, "", projBuildJobs.CircleYaml.YamlString, chunksChan); err != nil {
					ctx.Logger().Error(err, "error chunking build yaml")
					errors = append(errors, err)

					continue
				}
			}

			scanCount := countOfProjectsScanned.Add(1)
			s.SetProgressComplete(
				int(scanCount),
				len(projects),
				fmt.Sprintf("Scanned %d/%d projects", scanCount, len(projects)),
				"", // this would be for resumption, but we're not currently using it
			)

			ctx.Logger().V(2).Info(fmt.Sprintf("scanned %d/%d projects", countOfProjectsScanned.Load(), len(projects)))

			return nil
		})
	}

	_ = s.jobPool.Wait()

	if len(errors) > 0 {
		ctx.Logger().Info("encountered errors during scanning", "count", len(errors), "errors", errors)
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

		ctx.Logger().V(2).Info("successfully listed projects", "project_count", len(projects))

		return projects, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("invalid credentials, status %d", resp.StatusCode)
	default:
		return nil, fmt.Errorf("unexpected status code: %d while listing projects", resp.StatusCode)
	}
}

func (s *Source) listProjectBuilds(ctx context.Context, proj *project) ([]BuildNum, error) {
	// the vcs url is in format //circleci.com/org-id/proj-id, so we need to remove the // and .com to use it in the API
	parsedURL, err := url.Parse(proj.VcsUrl)
	if err != nil {
		return nil, err
	}

	vcsURL := strings.ReplaceAll(parsedURL.Host, ".com", "") + parsedURL.Path // circleci/org-id/proj-id

	// update clean vcs url in the project for later use
	proj.VcsUrl = vcsURL

	ctx.Logger().V(5).Info("listing project builds with URL", "repo_name", proj.Reponame, "vcs_url", proj.VcsUrl)

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
		var rawBuilds []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&rawBuilds); err != nil {
			return nil, fmt.Errorf("cannot decode CircleCI project builds JSON: %w", err)
		}

		buildNums := make([]BuildNum, 0)
		for _, item := range rawBuilds {
			if bn, ok := item["build_num"].(float64); ok {
				buildNums = append(buildNums, BuildNum(bn))
			}
		}

		ctx.Logger().V(2).Info("successfully listed builds for project", "repo_name", proj.Reponame, "build_count", len(buildNums))

		return buildNums, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("no builds found for project: %s", proj.Reponame)
	default:
		return nil, fmt.Errorf("unexpected status code while fetching builds for project: %s", proj.Reponame)
	}
}

func (s *Source) listProjBuildJobs(ctx context.Context, proj *project, buildNum BuildNum) (*buildJobs, error) {
	ctx.Logger().V(5).Info(fmt.Sprintf("listing project: %s build: %d jobs", proj.Reponame, buildNum))
	// /project/circleci/org-id/proj-id/1
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/project/%s/%d", baseURL, proj.VcsUrl, buildNum), http.NoBody)
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

		ctx.Logger().V(2).Info("successfully listed project build jobs", "repo_name", proj.Reponame, "build_num", buildNum)

		return &buildResp, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d while fetching project: %s build: %d jobs", resp.StatusCode, proj.Reponame, buildNum)
	}
}

func (s *Source) getOutputUrlResponse(outputUrl string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, outputUrl, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(bodyBytes), nil
}

func (s *Source) chunk(ctx context.Context, proj project, buildNum BuildNum, stepName, chunkData string, chunksChan chan *sources.Chunk) error {
	linkURL := fmt.Sprintf("https://app.circleci.com/pipelines/%s/%s/%s/%d", proj.VCS, proj.Username, proj.Reponame, buildNum)

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(ctx, strings.NewReader(chunkData))
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
						Repository:  proj.Reponame,
						BuildNumber: int64(buildNum),
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
