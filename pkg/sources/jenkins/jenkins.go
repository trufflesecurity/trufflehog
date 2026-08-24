package jenkins

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/roundtripper"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_JENKINS
)

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	url      *url.URL
	user     string
	token    string
	header   *header
	client   *http.Client
	sources.Progress
}

type header struct {
	key   string
	value string
}

// Ensure the Source satisfies the interfaces at compile time.
// SourceUnitChunker is deliberately not implemented yet, which keeps
// SourceManager on the non-unit Chunks path for scans.
var (
	_ sources.Source                 = (*Source)(nil)
	_ sources.SourceUnitEnumerator   = (*Source)(nil)
	_ sources.SourceUnitUnmarshaller = (*Source)(nil)
)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_JENKINS
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// Init returns an initialized Jenkins source.
func (s *Source) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, _ int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.Jenkins
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	// Initialize the Jenkins client with a custom HTTP client.
	var opts []func(*roundtripper.RoundTripper)

	// If the user has specified to skip TLS verification, we add the WithInsecureTLS option.
	if conn.GetInsecureSkipVerifyTls() {
		opts = append(opts, roundtripper.WithInsecureTLS())
	}

	const retryDelay = time.Second * 30
	opts = append(opts,
		roundtripper.WithLogger(aCtx.Logger()),
		roundtripper.WithLogging(),
		roundtripper.WithRetryable(
			roundtripper.WithShouldRetry5XXDuration(retryDelay),
			roundtripper.WithShouldRetry401Duration(retryDelay),
		),
	)

	client := &http.Client{
		Transport: roundtripper.NewRoundTripper(nil, opts...),
	}

	s.client = client

	var unparsedURL string
	var authMethod string
	switch cred := conn.GetCredential().(type) {
	case *sourcespb.Jenkins_BasicAuth:
		unparsedURL = conn.Endpoint
		s.user = cred.BasicAuth.Username
		s.token = cred.BasicAuth.Password
		if len(s.token) == 0 {
			return errors.Errorf("Jenkins source basic auth credential requires 'password' to be specified")
		}
		log.RedactGlobally(s.token)
		authMethod = "basic"
	case *sourcespb.Jenkins_Header:
		unparsedURL = conn.Endpoint
		s.header = &header{
			key:   cred.Header.Key,
			value: cred.Header.Value,
		}
		log.RedactGlobally(cred.Header.GetValue())
		authMethod = "header"
	case *sourcespb.Jenkins_Unauthenticated:
		unparsedURL = conn.Endpoint
		authMethod = "none"
	default:
		return errors.Errorf("unknown or unspecified authentication method provided for Jenkins source %q (unauthenticated scans must be explicitly configured)", name)
	}

	s.url, err = url.Parse(unparsedURL)
	if err != nil || unparsedURL == "" {
		return errors.WrapPrefix(err, fmt.Sprintf("Invalid endpoint URL given for Jenkins source: %s", unparsedURL), 0)
	}

	aCtx.Logger().V(1).Info("initialized Jenkins source",
		"auth_method", authMethod,
		"url_raw", unparsedURL,
		"url_parsed", s.url.String())

	return nil
}

func (s *Source) NewRequest(method, url string, body io.Reader) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if s.header != nil {
		request.Header.Set(s.header.key, s.header.value)
		return request, nil
	}

	if s.user != "" && s.token != "" {
		request.SetBasicAuth(s.user, s.token)
	}
	return request, nil
}

// GetJenkinsJobs traverses the tree to find all jobs.
// Example response from http://localhost:8080/api/json?tree=jobs[name,url]{0,100}
// on our Jenkins instance:
//
//	{
//		"_class": "hudson.model.Hudson",
//		"jobs": [
//		  {
//			"_class": "com.cloudbees.hudson.plugins.folder.Folder",
//			"name": "folder1",
//			"url": "http://jenkins:8080/job/folder1/"
//		  },
//		  {
//			"_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
//			"name": "hon-test",
//			"url": "http://jenkins:8080/job/hon-test/"
//		  },
//		  {
//			"_class": "hudson.model.FreeStyleProject",
//			"name": "hon-test-project",
//			"url": "http://jenkins:8080/job/hon-test-project/"
//		  },
//		  {
//			"_class": "hudson.model.FreeStyleProject",
//			"name": "steeeve-freestyle-project",
//			"url": "http://jenkins:8080/job/steeeve-freestyle-project/"
//		  }
//		]
//	}
func (s *Source) GetJenkinsJobs(ctx context.Context) (JenkinsJobResponse, error) {
	baseUrl := *s.url
	objects, err := s.RecursivelyGetJenkinsObjectsForPath(ctx, baseUrl.Path)
	return objects, err
}

func (s *Source) RecursivelyGetJenkinsObjectsForPath(ctx context.Context, absolutePath string) (JenkinsJobResponse, error) {
	jobs := JenkinsJobResponse{}

	collect := func(_ context.Context, job JenkinsJob) error {
		jobs.Jobs = append(jobs.Jobs, job)
		return nil
	}
	// Returning the error aborts the whole walk, which is the fail-fast
	// behavior callers of this method have always had.
	failFast := func(_ context.Context, err error) error { return err }

	err := s.walkJobs(ctx, absolutePath, collect, failFast)
	return jobs, err
}

// walkJobs traverses the Jenkins object tree beneath absolutePath, calling
// onJob for every scannable job it finds and onErr for every error it hits.
// Recursion continues unless onJob or onErr returns an error, which aborts the
// walk and is returned to the caller.
func (s *Source) walkJobs(
	ctx context.Context,
	absolutePath string,
	onJob func(context.Context, JenkinsJob) error,
	onErr func(context.Context, error) error,
) error {
	ctx.Logger().V(3).Info("getting objects",
		"path", absolutePath)

	objects, err := s.GetJenkinsObjectsForPath(ctx, absolutePath)
	if err != nil {
		return onErr(ctx, errors.WrapPrefix(err, fmt.Sprintf("failed to get Jenkins objects for path %q", absolutePath), 0))
	}
	ctx.Logger().V(3).Info("got objects",
		"path", absolutePath,
		"count", len(objects.Jobs))

	for _, job := range objects.Jobs {
		if common.IsDone(ctx) {
			return ctx.Err()
		}

		ctx.Logger().V(3).Info("processing object",
			"object_name", job.Name,
			"object_class", job.Class,
			"object_url", job.Url)

		if job.Class == "com.cloudbees.hudson.plugins.folder.Folder" {
			u, err := url.Parse(job.Url)
			if err != nil {
				if err := onErr(ctx, fmt.Errorf("failed to parse folder URL %q: %w", job.Url, err)); err != nil {
					return err
				}
				continue
			}
			if err := s.walkJobs(ctx, u.Path, onJob, onErr); err != nil {
				return err
			}
		} else {
			if job.Class == "hudson.model.FreeStyleProject" ||
				job.Class == "org.jenkinsci.plugins.workflow.job.WorkflowJob" {
				if err := onJob(ctx, job); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Source) GetJenkinsObjectsForPath(ctx context.Context, absolutePath string) (JenkinsJobResponse, error) {
	baseUrl := *s.url
	res := JenkinsJobResponse{}
	for i := 0; true; i += 100 {
		baseUrl.Path = path.Join(absolutePath, "api/json")
		params := url.Values{}
		params.Set("tree", fmt.Sprintf("jobs[name,url]{%d,%d}", i, i+100))
		baseUrl.RawQuery = params.Encode()

		ctx.Logger().V(4).Info("executing query", "query_url", baseUrl.String())
		req, err := s.NewRequest(http.MethodGet, baseUrl.String(), nil)
		if err != nil {
			return res, errors.WrapPrefix(err, "Failed to create new request to get jenkins jobs", 0)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return res, errors.WrapPrefix(err, "Failed to do get jenkins jobs request", 0)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return res, errors.New(fmt.Sprintf("Received non-200 status from get jenkins jobs request: %d", resp.StatusCode))
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType != "" && !strings.Contains(contentType, "application/json") {
			return res, errors.New(fmt.Sprintf("Received unexpected Content-Type from get jenkins jobs request: %s", contentType))
		}

		jobResp := &JenkinsJobResponse{}
		err = json.NewDecoder(resp.Body).Decode(jobResp)
		if err != nil {
			return res, errors.WrapPrefix(err, "Failed to decode get jenkins jobs response", 0)
		}
		res.Jobs = append(res.Jobs, jobResp.Jobs...)
		if len(jobResp.Jobs) < 100 {
			break
		}
	}
	return res, nil
}

func (s *Source) GetJenkinsBuilds(ctx context.Context, jobAbsolutePath string) (JenkinsBuildResponse, error) {
	ctx = context.WithValues(ctx,
		"job_path", jobAbsolutePath)

	ctx.Logger().V(2).Info("getting builds")

	builds := JenkinsBuildResponse{}
	buildsUrl := *s.url
	for i := 0; true; i += 100 {
		buildsUrl.Path = path.Join(jobAbsolutePath, "api/json")
		params := url.Values{}
		params.Set("tree", fmt.Sprintf("builds[number,url]{%d,%d}", i, i+100))
		buildsUrl.RawQuery = params.Encode()
		req, err := s.NewRequest(http.MethodGet, buildsUrl.String(), nil)
		if err != nil {
			return builds, errors.WrapPrefix(err, "Failed to create new request to get jenkins builds", 0)
		}

		ctx.Logger().V(4).Info("executing query", "query_url", req.URL.String())
		resp, err := s.client.Do(req)
		if err != nil {
			return builds, errors.WrapPrefix(err, "Failed to do get jenkins builds request", 0)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return builds, errors.New(fmt.Sprintf("Received non-200 status from get jenkins builds request: %d", resp.StatusCode))
		}

		contentType := resp.Header.Get("Content-Type")
		if contentType != "" && !strings.Contains(contentType, "application/json") {
			return builds, errors.New(fmt.Sprintf("Received unexpected Content-Type from get jenkins builds request: %s", contentType))
		}

		buildResp := &JenkinsBuildResponse{}
		err = json.NewDecoder(resp.Body).Decode(buildResp)
		if err != nil {
			return builds, errors.WrapPrefix(err, "Failed to decode get jenkins builds response", 0)
		}
		builds.Builds = append(builds.Builds, buildResp.Builds...)
		if len(buildResp.Builds) < 100 {
			break
		}
	}
	return builds, nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	jobs, err := s.GetJenkinsJobs(ctx)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to get Jenkins job response", 0)
	}
	ctx.Logger().V(1).Info("got jobs", "count", len(jobs.Jobs))

	for i, project := range jobs.Jobs {
		if common.IsDone(ctx) {
			return nil
		}

		ctx := context.WithValues(ctx,
			"job_name", project.Name,
			"job_class", project.Class,
			"job_url", project.Url)

		s.SetProgressComplete(i, len(jobs.Jobs), fmt.Sprintf("Project: %s", project.Name), "")

		parsedUrl, err := url.Parse(project.Url)
		if err != nil {
			ctx.Logger().Error(err, "failed to parse job URL; skipping job")
			continue
		}
		projectURL := *s.url
		projectURL.Path = parsedUrl.Path

		builds, err := s.GetJenkinsBuilds(ctx, projectURL.Path)
		if err != nil {
			ctx.Logger().Error(err, "failed to get builds; skipping job")
			continue
		}
		ctx.Logger().V(2).Info("got builds",
			"count", len(builds.Builds))

		for _, build := range builds.Builds {
			if common.IsDone(ctx) {
				return nil
			}

			ctx := context.WithValues(ctx,
				"build_number", build.Number,
				"build_url", build.Url)

			if err := s.chunkBuild(ctx, build, project.Name, chunksChan); err != nil {
				ctx.Logger().Error(err, "error scanning build log")
			}
		}
	}

	s.SetProgressComplete(len(jobs.Jobs), len(jobs.Jobs), fmt.Sprintf("Done scanning source %s", s.name), "")
	return nil
}

// chunkBuild takes build information and sends it to the chunksChan.
// It also logs all errors that occur and does not return them, as the parent context expects to continue running.
func (s *Source) chunkBuild(
	ctx context.Context,
	build JenkinsBuild,
	projectName string,
	chunksChan chan *sources.Chunk,
) error {
	ctx.Logger().V(2).Info("chunking build")

	parsedUrl, err := url.Parse(build.Url)
	if err != nil {
		return fmt.Errorf("failed to parse build URL %q: %w", build.Url, err)
	}
	buildLogURL := *s.url
	buildLogURL.Path = path.Join(parsedUrl.Path, "consoleText")
	ctx = context.WithValues(ctx,
		"build_log_url", buildLogURL.String())

	req, err := s.NewRequest(http.MethodGet, buildLogURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request to %q: %w", buildLogURL.String(), err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("could not retrieve build log from %q: %w", buildLogURL.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("got unexpected HTTP status code %v when trying to retrieve build log from %q",
			resp.StatusCode,
			buildLogURL.String())
	}

	chunkSkel := &sources.Chunk{
		SourceName: s.name,
		SourceID:   s.SourceID(),
		SourceType: s.Type(),
		JobID:      s.JobID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Jenkins{
				Jenkins: &source_metadatapb.Jenkins{
					ProjectName: projectName,
					BuildNumber: build.Number,
					Link:        buildLogURL.String(),
				},
			},
		},
		SourceVerify: s.verify,
	}

	ctx.Logger().V(4).Info("scanning build log")
	return handlers.HandleFile(ctx, resp.Body, chunkSkel, sources.ChanReporter{Ch: chunksChan})
}

// Enumerate implements the SourceUnitEnumerator interface. It reports one unit
// per Jenkins job, walking folders recursively. A folder that cannot be listed
// is reported to the UnitReporter and the rest of the walk continues.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	baseUrl := *s.url
	return s.walkJobs(ctx, baseUrl.Path,
		func(ctx context.Context, job JenkinsJob) error {
			parsedUrl, err := url.Parse(job.Url)
			if err != nil {
				return reporter.UnitErr(ctx, fmt.Errorf("failed to parse job URL %q: %w", job.Url, err))
			}
			// Only the path is retained, matching how Chunks rebases a job
			// URL onto the configured endpoint.
			return reporter.UnitOk(ctx, JobUnit{Path: strings.TrimSuffix(parsedUrl.Path, "/")})
		},
		reporter.UnitErr,
	)
}

// UnmarshalSourceUnit implements the SourceUnitUnmarshaller interface. It
// accepts three shapes: the persisted envelope carrying unit_data (round-trips
// the unit exactly), the envelope without unit_data (rebuilt from id), and a
// bare JobUnit.
func (s *Source) UnmarshalSourceUnit(data []byte) (sources.SourceUnit, error) {
	var envelope unitEnvelope
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Kind == string(SourceUnitKindJob) {
		if envelope.UnitData != "" {
			if decoded, err := base64.StdEncoding.DecodeString(envelope.UnitData); err == nil {
				var unit JobUnit
				if json.Unmarshal(decoded, &unit) == nil && unit.Path != "" {
					return unit, nil
				}
			}
		}
		if envelope.ID != "" {
			return JobUnit{Path: envelope.ID}, nil
		}
	}

	var unit JobUnit
	if err := json.Unmarshal(data, &unit); err != nil {
		return nil, err
	}
	if unit.Path == "" {
		return nil, errors.New("not a Jenkins JobUnit")
	}
	return unit, nil
}

type JenkinsJobResponse struct {
	Jobs []JenkinsJob `json:"jobs"`
}

type JenkinsJob struct {
	Class string `json:"_class"`
	Name  string `json:"name"`
	Url   string `json:"url"`
}

type JenkinsBuildResponse struct {
	Builds []JenkinsBuild `json:"builds"`
}

type JenkinsBuild struct {
	Number int64  `json:"number"`
	Url    string `json:"url"`
}
