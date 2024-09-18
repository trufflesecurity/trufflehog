package jenkins

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
	log      logr.Logger
	client   *http.Client
	sources.Progress
}

type header struct {
	key   string
	value string
}

// Ensure the Source satisfies the interface at compile time
var _ sources.Source = (*Source)(nil)

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
	s.log = aCtx.Logger()

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
		roundtripper.WithLogger(s.log),
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
	switch cred := conn.GetCredential().(type) {
	case *sourcespb.Jenkins_BasicAuth:
		unparsedURL = conn.Endpoint
		s.user = cred.BasicAuth.Username
		s.token = cred.BasicAuth.Password
		if len(s.token) == 0 {
			return errors.Errorf("Jenkins source basic auth credential requires 'password' to be specified")
		}
	case *sourcespb.Jenkins_Header:
		unparsedURL = conn.Endpoint
		s.header = &header{
			key:   cred.Header.Key,
			value: cred.Header.Value,
		}
	case *sourcespb.Jenkins_Unauthenticated:
		unparsedURL = conn.Endpoint
	default:
		return errors.Errorf("Invalid configuration given for source. Name: %s, Type: %s", name, s.Type())
	}

	s.url, err = url.Parse(unparsedURL)
	if err != nil || unparsedURL == "" {
		return errors.WrapPrefix(err, fmt.Sprintf("Invalid endpoint URL given for Jenkins source: %s", unparsedURL), 0)
	}

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
	objects, err := s.GetJenkinsObjectsForPath(ctx, absolutePath)
	if err != nil {
		return jobs, err
	}

	for _, job := range objects.Jobs {
		if job.Class == "com.cloudbees.hudson.plugins.folder.Folder" {
			u, err := url.Parse(job.Url)
			if err != nil {
				return jobs, err
			}
			objects, err := s.RecursivelyGetJenkinsObjectsForPath(ctx, u.Path)
			if err != nil {
				return jobs, err
			}
			jobs.Jobs = append(jobs.Jobs, objects.Jobs...)
		} else {
			if job.Class == "hudson.model.FreeStyleProject" ||
				job.Class == "org.jenkinsci.plugins.workflow.job.WorkflowJob" {
				jobs.Jobs = append(jobs.Jobs, job)
			}
		}
	}
	return jobs, nil
}

func (s *Source) GetJenkinsObjectsForPath(ctx context.Context, absolutePath string) (JenkinsJobResponse, error) {
	baseUrl := *s.url
	res := JenkinsJobResponse{}
	for i := 0; true; i += 100 {
		baseUrl.Path = path.Join(absolutePath, "api/json")
		baseUrl.RawQuery = fmt.Sprintf("tree=jobs[name,url]{%d,%d}", i, i+100)

		req, err := s.NewRequest(http.MethodGet, baseUrl.String(), nil)
		if err != nil {
			return res, errors.WrapPrefix(err, "Failed to create new request to get jenkins jobs", 0)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return res, errors.WrapPrefix(err, "Failed to do get jenkins jobs request", 0)
		}
		defer resp.Body.Close()

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
	builds := JenkinsBuildResponse{}
	buildsUrl := *s.url
	for i := 0; true; i += 100 {
		buildsUrl.Path = path.Join(jobAbsolutePath, "/api/json")
		buildsUrl.RawQuery = fmt.Sprintf("tree=builds[number,url]{%d,%d}", i, i+100)
		req, err := s.NewRequest(http.MethodGet, buildsUrl.String(), nil)
		if err != nil {
			return builds, errors.WrapPrefix(err, "Failed to create new request to get jenkins builds", 0)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return builds, errors.WrapPrefix(err, "Failed to do get jenkins builds request", 0)
		}
		defer resp.Body.Close()

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

	for i, project := range jobs.Jobs {
		if common.IsDone(ctx) {
			return nil
		}

		s.SetProgressComplete(i, len(jobs.Jobs), fmt.Sprintf("Project: %s", project.Name), "")

		parsedUrl, err := url.Parse(project.Url)
		if err != nil {
			s.log.Error(err, "Failed to parse Jenkins project URL, skipping project", "url", project.Url, "project", project.Name)
			continue
		}
		projectURL := *s.url
		projectURL.Path = parsedUrl.Path

		builds, err := s.GetJenkinsBuilds(ctx, projectURL.Path)
		if err != nil {
			s.log.Error(err, "Failed to get Jenkins build response, skipping project", "project", project.Name)
			continue
		}

		for _, build := range builds.Builds {
			if common.IsDone(ctx) {
				return nil
			}

			s.chunkBuild(ctx, build, project.Name, chunksChan)
		}
	}

	s.SetProgressComplete(len(jobs.Jobs), len(jobs.Jobs), fmt.Sprintf("Done scanning source %s", s.name), "")
	return nil
}

// chunkBuild takes build information and sends it to the chunksChan.
// It also logs all errors that occur and does not return them, as the parent context expects to continue running.
func (s *Source) chunkBuild(_ context.Context, build JenkinsBuild, projectName string, chunksChan chan *sources.Chunk) {
	// Setup a logger to identify the build and project.
	chunkBuildLog := s.log.WithValues(
		"build", build.Number,
		"project", projectName,
	)

	parsedUrl, err := url.Parse(build.Url)
	if err != nil {
		chunkBuildLog.Error(err, "Failed to parse Jenkins build URL, skipping build", "url", build.Url)
		return
	}
	buildLogURL := *s.url
	buildLogURL.Path = path.Join(parsedUrl.Path, "consoleText")

	req, err := s.NewRequest(http.MethodGet, buildLogURL.String(), nil)
	if err != nil {
		chunkBuildLog.Error(err, "Failed to create new request to Jenkins, skipping build")
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		chunkBuildLog.Error(err, "Failed to get build log in Jenkins chunks, skipping build")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		chunkBuildLog.Error(err, "Status Code from build was unexpected, skipping build", "status_code", resp.StatusCode)
		return
	}

	buildLog, err := io.ReadAll(resp.Body)
	if err != nil {
		chunkBuildLog.Error(err, "Failed to read body from the build log response, skipping build")
		return
	}

	chunksChan <- &sources.Chunk{
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
		Data:   buildLog,
		Verify: s.verify,
	}
}

type JenkinsJobResponse struct {
	Jobs []struct {
		Class string `json:"_class"`
		Name  string `json:"name"`
		Url   string `json:"url"`
	} `json:"jobs"`
}

type JenkinsBuildResponse struct {
	Builds []JenkinsBuild `json:"builds"`
}

type JenkinsBuild struct {
	Number int64  `json:"number"`
	Url    string `json:"url"`
}
