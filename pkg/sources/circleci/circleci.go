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
)

// CircleCI has released API v2, but we're continuing to use v1.1
// Because v1.1 still supports listing endpoints and remains officially supported.
// It is a var so tests can point it at a fake server.
var baseURL = "https://circleci.com/api/v1.1"

// errOutputExpired means a step's output is gone. CircleCI deletes step output
// after its retention period, so old builds return 403 or 404 for it. That is
// expected, so the step is skipped instead of reported as an error.
var errOutputExpired = errors.New("step output expired")

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
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	s.jobPool = &errgroup.Group{}
	s.jobPool.SetLimit(concurrency)
	s.client = common.RetryableHTTPClientTimeout(3, common.WithAPILogHooks("circleci"))

	var conn sourcespb.CircleCI
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	authType := "none"
	switch conn.Credential.(type) {
	case *sourcespb.CircleCI_Token:
		s.token = conn.GetToken()
		log.RedactGlobally(s.token)
		authType = "token"
	}

	ctx.Logger().V(1).Info("CircleCI source initialized", "auth_type", authType, "concurrency", concurrency)

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
	scanErrs := sources.NewScanErrors()

	for _, project := range projects {
		projectCtx := context.WithValues(ctx, "repository_name", project.Reponame)

		s.jobPool.Go(func() error {
			projectCtx.Logger().V(2).Info("Scanning project")
			projectBuilds, err := s.listProjectBuilds(projectCtx, &project)
			if err != nil {
				projectCtx.Logger().Error(err, "Failed to list builds for project")
				scanErrs.Add(err)

				return nil
			}

			for _, buildNum := range projectBuilds {
				buildCtx := context.WithValues(projectCtx, "build_number", buildNum)

				projBuildJobs, err := s.listProjBuildJobs(buildCtx, &project, buildNum)
				if err != nil {
					buildCtx.Logger().Error(err, "Failed to get steps for build")
					scanErrs.Add(err)

					continue
				}
				buildCtx.Logger().V(3).Info("Scanning build", "steps", len(projBuildJobs.Steps))

				for _, step := range projBuildJobs.Steps {
					for _, action := range step.Actions {
						// The output URL is signed, so it is never logged.
						buildCtx.Logger().V(4).Info("Scanning step output", "step", step.Name)
						data, err := s.getOutputUrlResponse(buildCtx, action.OutputUrl)
						if errors.Is(err, errOutputExpired) {
							buildCtx.Logger().V(4).Info("Skipping step output", "step", step.Name, "reason", "output expired")

							continue
						}
						if err != nil {
							buildCtx.Logger().Error(err, "Failed to get step output", "step", step.Name)
							scanErrs.Add(err)

							continue
						}

						if err = s.chunk(buildCtx, project, buildNum, step.Name, data, chunksChan); err != nil {
							buildCtx.Logger().Error(err, "Failed to chunk step output", "step", step.Name)
							scanErrs.Add(err)

							continue
						}
					}
				}

				if err = s.chunk(buildCtx, project, buildNum, "", projBuildJobs.CircleYaml.YamlString, chunksChan); err != nil {
					buildCtx.Logger().Error(err, "Failed to chunk build yaml")
					scanErrs.Add(err)

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

			projectCtx.Logger().V(2).Info("Finished scanning project", "scanned", scanCount, "total", len(projects))

			return nil
		})
	}

	_ = s.jobPool.Wait()

	if scanErrs.Count() > 0 {
		ctx.Logger().Error(scanErrs.Errors(), "Failed to scan some projects", "error_count", scanErrs.Count())
	}

	return nil
}

// listAllProjects lists all the projects the token can access
func (s *Source) listAllProjects(ctx context.Context) ([]project, error) {
	ctx.Logger().V(1).Info("Listing projects")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/projects", baseURL), http.NoBody)
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

		ctx.Logger().V(1).Info("Listed projects", "count", len(projects))

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

	ctx.Logger().V(5).Info("Listing project builds", "vcs_url", proj.VcsUrl)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/project/%s", baseURL, vcsURL), http.NoBody)
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

		ctx.Logger().V(2).Info("Listed builds", "count", len(buildNums))

		return buildNums, nil
	case http.StatusNotFound:
		// A project with no builds is not an error, there is just nothing to scan.
		ctx.Logger().V(4).Info("Skipping project", "reason", "no builds")
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d while fetching builds for project: %s", resp.StatusCode, proj.Reponame)
	}
}

func (s *Source) listProjBuildJobs(ctx context.Context, proj *project, buildNum BuildNum) (*buildJobs, error) {
	ctx.Logger().V(5).Info("Fetching build")
	// /project/circleci/org-id/proj-id/1
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/project/%s/%d", baseURL, proj.VcsUrl, buildNum), http.NoBody)
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

		return &buildResp, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d while fetching project: %s build: %d jobs", resp.StatusCode, proj.Reponame, buildNum)
	}
}

func (s *Source) getOutputUrlResponse(ctx context.Context, outputUrl string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, outputUrl, nil)
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

	// An error page must never be scanned as build output.
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return "", errOutputExpired
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d while fetching step output", resp.StatusCode)
	}

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
			SourceVerify: s.verify,
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
