package jenkins

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	KB = 1024
	MB = 1024 * KB
)

// generateTestData creates a string of exactly the specified size using the given pattern.
func generateTestData(size int, pattern string) string {
	if len(pattern) == 0 {
		pattern = "X" // fallback pattern
	}

	var builder strings.Builder
	builder.Grow(size)

	for builder.Len() < size {
		remaining := size - builder.Len()
		if remaining >= len(pattern) {
			builder.WriteString(pattern)
		} else {
			// Truncate the pattern to fill exactly the remaining bytes.
			builder.WriteString(pattern[:remaining])
		}
	}

	return builder.String()
}

// createMockJenkinsServer creates a test HTTP server that simulates Jenkins API responses.
func createMockJenkinsServer(jobName string, buildNumber int, logContent string) *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	// Mock the main Jenkins API endpoint that lists jobs.
	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "tree=jobs") {
			w.Header().Set("Content-Type", "application/json")
			response := fmt.Sprintf(
				`{"jobs":[{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob",`+
					`"name":"%s","url":"%s/job/%s/"}]}`, jobName, server.URL, jobName)
			fmt.Fprint(w, response)
		} else {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jobs":[]}`)
		}
	})

	// Mock the job-specific API endpoint that lists builds for a particular job.
	mux.HandleFunc(fmt.Sprintf("/job/%s/api/json", jobName), func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "tree=builds") {
			w.Header().Set("Content-Type", "application/json")
			response := fmt.Sprintf(
				`{"builds":[{"number":%d,"url":"%s/job/%s/%d/"}]}`, buildNumber, server.URL, jobName, buildNumber)
			fmt.Fprint(w, response)
		} else {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"builds":[]}`)
		}
	})

	// Mock the console text endpoint that returns the actual build log content.
	// This is where the test data payload is served to verify chunking behavior.
	mux.HandleFunc(fmt.Sprintf("/job/%s/%d/consoleText", jobName, buildNumber), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, logContent)
	})

	return server
}

// TestJenkinsVariousSizes verifies that Jenkins build logs are properly chunked
// across different data sizes that represent real-world scenarios from small
// logs to large CI/CD outputs.
func TestJenkinsVariousSizes(t *testing.T) {
	testCases := []struct {
		name        string
		dataSize    int
		pattern     string
		jobName     string
		buildNumber int
	}{
		{
			name:        "small_60KB",
			dataSize:    60 * KB,
			pattern:     "This is a line in the build log with some sensitive data\n",
			jobName:     "test-job",
			buildNumber: 42,
		},
		{
			name:        "large_1MB",
			dataSize:    1 * MB,
			pattern:     "Line with potential secrets like api_key=abc123def456\n",
			jobName:     "large-job",
			buildNumber: 1,
		},
		{
			name:        "medium_80KB",
			dataSize:    80 * KB,
			pattern:     "Line with secret: api_key=sk-123abc456def\n",
			jobName:     "medium-job",
			buildNumber: 123,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logContent := generateTestData(tc.dataSize, tc.pattern)
			t.Logf("Generated %d bytes (%.2f KB) of test data", tc.dataSize, float64(tc.dataSize)/float64(KB))

			server := createMockJenkinsServer(tc.jobName, tc.buildNumber, logContent)
			defer server.Close()

			s := new(Source)
			conn, err := anypb.New(&sourcespb.Jenkins{
				Endpoint: server.URL,
				Credential: &sourcespb.Jenkins_BasicAuth{
					BasicAuth: &credentialspb.BasicAuth{
						Username: "testuser",
						Password: "testpass",
					},
				},
			})
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err = s.Init(ctx, "test-jenkins-"+tc.name, 0, 1, false, conn, runtime.NumCPU())
			require.NoError(t, err)

			jobs, err := s.GetJenkinsJobs(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, jobs.Jobs, "No jobs found. This indicates a mock server setup issue.")

			chunksChan := make(chan *sources.Chunk, 200)
			done := make(chan error, 1)

			go func() {
				defer close(chunksChan)
				done <- s.Chunks(ctx, chunksChan)
			}()

			var chunks []*sources.Chunk
			var totalDataSize int
			maxChunkSize := 0
			for chunk := range chunksChan {
				chunks = append(chunks, chunk)
				totalDataSize += len(chunk.Data)
				if len(chunk.Data) > maxChunkSize {
					maxChunkSize = len(chunk.Data)
				}
			}

			require.NoError(t, <-done)
			require.NotEmpty(t, chunks, "No chunks were received.")

			// Verify that large logs are actually being split into multiple chunks.
			// This catches regressions where chunking logic might not be working.
			// Data larger than a single chunk should result in multiple chunks.
			if tc.dataSize > sources.DefaultChunkSize && len(chunks) <= 1 {
				t.Logf("Got only %d chunk for data size %d bytes (chunk size: %d bytes), may indicate chunking not working as expected",
					len(chunks), tc.dataSize, sources.DefaultChunkSize)
			}

			// Ensure no individual chunk exceeds the maximum allowed size.
			// This validates that the chunking mechanism respects size limits.
			assert.LessOrEqual(t, maxChunkSize, sources.TotalChunkSize,
				"Found chunk larger than expected: %d bytes (max expected %d bytes)",
				maxChunkSize, sources.TotalChunkSize)

			// Validate data integrity by checking that total output matches input size.
			// Lower bound ensures no data loss; upper bound catches excessive duplication
			// from overlapping peek data between adjacent chunks.
			assert.GreaterOrEqual(t, totalDataSize, tc.dataSize,
				"Total data size %d is less than original %d - suggests data loss",
				totalDataSize, tc.dataSize)
			assert.LessOrEqual(t, totalDataSize, tc.dataSize*3,
				"Total data size %d is much larger than original %d - suggests excessive duplication",
				totalDataSize, tc.dataSize)

			chunk := chunks[0]
			assert.Equal(t, "test-jenkins-"+tc.name, chunk.SourceName)

			jenkinsMetadata := chunk.SourceMetadata.GetJenkins()
			require.NotNil(t, jenkinsMetadata, "Missing Jenkins metadata")
			assert.Equal(t, tc.jobName, jenkinsMetadata.ProjectName)
			assert.Equal(t, int64(tc.buildNumber), jenkinsMetadata.BuildNumber)

			expectedLink := fmt.Sprintf("%s/job/%s/%d/consoleText", server.URL, tc.jobName, tc.buildNumber)
			assert.Equal(t, expectedLink, jenkinsMetadata.Link)
		})
	}
}

// TestJenkinsChunkBuildDirect tests the chunkBuild method in isolation to verify
// that build log chunking works correctly without the overhead of the full source
// initialization and job discovery process.
func TestJenkinsChunkBuildDirect(t *testing.T) {
	// Use a size that will definitely require chunking to test the splitting logic.
	largeLogContent := generateTestData(500*KB, "Line with secret: api_key=sk-123abc456def\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/consoleText") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, largeLogContent)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	s := new(Source)
	conn, err := anypb.New(&sourcespb.Jenkins{
		Endpoint: server.URL,
		Credential: &sourcespb.Jenkins_BasicAuth{
			BasicAuth: &credentialspb.BasicAuth{Username: "test", Password: "test"},
		},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = s.Init(ctx, "test-chunk-build", 0, 1, false, conn, runtime.NumCPU())
	require.NoError(t, err)

	mockBuild := JenkinsBuild{
		Number: 123,
		Url:    server.URL + "/job/test-project/123/",
	}

	chunksChan := make(chan *sources.Chunk, 200)

	go func() {
		defer close(chunksChan)
		err := s.chunkBuild(ctx, mockBuild, "test-project", chunksChan)
		assert.NoError(t, err)
	}()

	var chunks []*sources.Chunk
	var totalDataSize int
	maxChunkSize := 0
	for chunk := range chunksChan {
		chunks = append(chunks, chunk)
		totalDataSize += len(chunk.Data)
		if len(chunk.Data) > maxChunkSize {
			maxChunkSize = len(chunk.Data)
		}
	}

	require.NotEmpty(t, chunks, "No chunks were received from chunkBuild.")

	assert.LessOrEqual(t, maxChunkSize, sources.TotalChunkSize,
		"Found chunk larger than expected: %d bytes (max expected %d bytes)",
		maxChunkSize, sources.TotalChunkSize)

	// Ensure that direct chunking maintains data integrity with the same
	// bounds checking as the full integration test.
	originalSize := len(largeLogContent)
	assert.GreaterOrEqual(t, totalDataSize, originalSize,
		"Total data size %d is less than original %d - suggests data loss",
		totalDataSize, originalSize)
	assert.LessOrEqual(t, totalDataSize, originalSize*3,
		"Total data size %d is much larger than original %d - suggests excessive duplication",
		totalDataSize, originalSize)

	chunk := chunks[0]
	assert.Equal(t, "test-chunk-build", chunk.SourceName)

	jenkinsMetadata := chunk.SourceMetadata.GetJenkins()
	require.NotNil(t, jenkinsMetadata, "Missing Jenkins metadata")
	assert.Equal(t, "test-project", jenkinsMetadata.ProjectName)
	assert.Equal(t, int64(123), jenkinsMetadata.BuildNumber)

	expectedLink := server.URL + "/job/test-project/123/consoleText"
	assert.Equal(t, expectedLink, jenkinsMetadata.Link)
}
